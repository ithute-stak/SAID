"""Tamper-evident per-investigation event hashes and retention dry-run.

A hash chain detects accidental/unauthorized row alteration but is NOT a
cryptographic external timestamp, WORM store or a substitute for DB grants.
"""
import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.exc import IntegrityError, OperationalError

from said.main import Base, database
from said.ceir.api import require_central
from said.ceir.quality import MockInvestigation, MockObservation

router = APIRouter(prefix="/api/v1/ceir/sandbox/governance",
                   tags=["SAID Intelligence sandbox governance"])

ZERO_DIGEST = "0" * 64

class ReviewLedger(Base):
    __tablename__ = "ceir_mock_review_ledger"
    __table_args__ = (UniqueConstraint("investigation_id", "sequence",
                                       name="uq_ceir_review_ledger_sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_investigations.id"),
                                                 nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    actor_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    decision_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    previous_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

def digest_of(row: ReviewLedger) -> str:
    data = json.dumps({
        "id": row.id, "investigation_id": row.investigation_id,
        "sequence": row.sequence, "action": row.action, "actor": row.actor_reference,
        "decision_reference": row.decision_reference,
        "previous_digest": row.previous_digest,
        "created_at": row.created_at.replace(tzinfo=None).isoformat(),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def lock_case(db: Session, case_id: str) -> MockInvestigation:
    """Acquire owning investigation lock before child-state writes."""
    row = db.scalar(select(MockInvestigation).where(
        MockInvestigation.id == case_id).with_for_update())
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return row


def commit_case(db: Session):
    """Commit atomically; never blindly retry governance side effects.

    Deadlocks and serialization errors require a NEW authorized request and
    freshly validated state, not a replay inside a failed transaction.
    """
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent case write conflict") from None
    except OperationalError as exc:
        db.rollback()
        sqlstate = getattr(getattr(exc, "orig", None), "sqlstate", None)
        if sqlstate in {"40P01", "40001", "55P03"}:
            raise HTTPException(status_code=409, detail="Transient transaction conflict; re-evaluate case before retry") from None
        raise


def append_event(db: Session, case_id: str, action: str, actor: str, reference: str):
    # Serialize ledger writers using the owning investigation row on PostgreSQL.
    # SQLite lacks SELECT FOR UPDATE; its single-writer behavior and the unique
    # (investigation_id, sequence) constraint remain secondary safeguards.
    lock_case(db, case_id)
    history = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case_id).order_by(ReviewLedger.sequence)).all()
    previous = ZERO_DIGEST
    for index, old in enumerate(history, start=1):
        if old.sequence != index or old.previous_digest != previous or old.digest != digest_of(old):
            raise HTTPException(status_code=409, detail="Review ledger integrity conflict")
        previous = old.digest
    event = ReviewLedger(
        id=str(uuid.uuid4()), investigation_id=case_id, sequence=len(history) + 1,
        action=action, actor_reference=actor, decision_reference=reference,
        previous_digest=previous, digest="",
        created_at=datetime.now(timezone.utc),
    )
    event.digest = digest_of(event)
    db.add(event)

@router.get("/investigations/{investigation_id}/integrity")
def verify(investigation_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    if db.get(MockInvestigation, investigation_id) is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    events = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == investigation_id).order_by(ReviewLedger.sequence)).all()
    previous = ZERO_DIGEST
    for index, event in enumerate(events, start=1):
        if event.sequence != index or event.previous_digest != previous or event.digest != digest_of(event):
            return {"investigation_id": investigation_id, "valid": False,
                    "events_checked": index, "simulated": True}
        previous = event.digest
    return {"investigation_id": investigation_id, "valid": bool(events),
            "events_checked": len(events), "simulated": True}

@router.get("/retention/preview")
def retention_preview(request: Request, db: Session = Depends(database)):
    require_central(request)
    raw = os.getenv("SAID_MOCK_RETENTION_DAYS", "90")
    try:
        days = int(raw)
    except ValueError:
        raise HTTPException(status_code=503, detail="Invalid retention configuration")
    if not 7 <= days <= 365:
        raise HTTPException(status_code=503, detail="Invalid retention configuration")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    # Read-only; never delete evidence or break chain/foreign keys.
    from said.ceir.appeals import MockAppeal
    from said.ceir.oversight import LegalHold
    # This read-only preview excludes records tied to active legal holds,
    # pending appeals, or any open human investigation.
    rows = db.scalars(select(MockObservation).where(
        MockObservation.created_at < cutoff).order_by(MockObservation.created_at)
        .limit(100)).all()
    eligible = []
    protected = []
    for obs in rows:
        case = db.scalar(select(MockInvestigation).where(
            MockInvestigation.observation_id == obs.id))
        if case is not None:
            hold = db.scalar(select(LegalHold.id).where(
                LegalHold.investigation_id == case.id, LegalHold.active.is_(True)))
            appeal = db.scalar(select(MockAppeal.id).where(
                MockAppeal.investigation_id == case.id,
                MockAppeal.state == "pending_supervisor"))
            if hold or appeal or case.status == "pending_human_review":
                protected.append(obs.id)
                continue
        eligible.append(obs.id)
    return {"retention_days": days, "cutoff": cutoff.isoformat(),
            "old_observation_ids": eligible,
            "excluded_protected_ids": protected,
            "preview_only": True, "records_deleted": 0, "simulated": True}
