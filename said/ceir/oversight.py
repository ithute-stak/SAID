"""Central CEIR oversight — sandbox-only supervisory views and audit checkpoints.

Checkpoints anchor a local investigation-ledger HEAD into a separate table.
They support later external anchoring, but this service does not provide WORM
or independent external proof. No source data deletion or real network action.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.ceir.api import require_central
from said.ceir.appeals import MockAppeal
from said.ceir.quality import MockInvestigation
from said.ceir.governance import ReviewLedger, ZERO_DIGEST, digest_of

router = APIRouter(prefix="/api/v1/ceir/sandbox/oversight",
                   tags=["CEIR simulated supervisory oversight"])


class MockCheckpoint(Base):
    __tablename__ = "ceir_mock_checkpoints"
    __table_args__ = (UniqueConstraint("investigation_id", "sequence",
                                       name="uq_ceir_checkpoint_case_sequence"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("ceir_mock_investigations.id"), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(nullable=False)
    head_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    checkpoint_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc))


class LegalHold(Base):
    __tablename__ = "ceir_mock_legal_holds"
    __table_args__ = (UniqueConstraint("investigation_id", name="uq_ceir_legal_hold_case"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("ceir_mock_investigations.id"), nullable=False)
    reason_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    active: Mapped[bool] = mapped_column(nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc))


class ReferenceInput(BaseModel):
    investigation_id: str = Field(min_length=36, max_length=36)
    reason_reference: str = Field(min_length=3, max_length=120,
                                  pattern=r"^[A-Za-z0-9_-]+$")


def supervisor(request: Request):
    actor = require_central(request)
    if "ceir_supervisor" not in actor.roles:
        raise HTTPException(status_code=403, detail="CEIR supervisor role required")
    return actor


def auditor(request: Request):
    actor = require_central(request)
    if not (actor.roles & {"ceir_supervisor", "ceir_auditor"}):
        raise HTTPException(status_code=403, detail="CEIR audit role required")
    return actor


def valid_head(db: Session, investigation_id: str):
    rows = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == investigation_id)
        .order_by(ReviewLedger.sequence)).all()
    if not rows:
        raise HTTPException(status_code=409, detail="No recorded investigation ledger")
    previous = ZERO_DIGEST
    for n, entry in enumerate(rows, 1):
        if entry.sequence != n or entry.previous_digest != previous or entry.digest != digest_of(entry):
            raise HTTPException(status_code=409, detail="Review ledger integrity conflict")
        previous = entry.digest
    return len(rows), previous


def checkpoint_hash(case_id: str, sequence: int, head: str, reason: str) -> str:
    content = json.dumps({"investigation_id": case_id, "sequence": sequence,
                          "head_digest": head, "reason_reference": reason}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@router.get("/summary")
def summary(request: Request, db: Session = Depends(database)):
    auditor(request)
    appeals = db.scalars(select(MockAppeal).order_by(MockAppeal.created_at).limit(100)).all()
    pending = sum(1 for a in appeals if a.state == "pending_supervisor")
    holds = db.scalars(select(LegalHold).where(LegalHold.active.is_(True)).limit(100)).all()
    return {"appeals_in_page": len(appeals), "pending_appeals_in_page": pending,
            "decided_appeals_in_page": len(appeals)-pending,
            "active_holds_in_page": len(holds),
            "page_limit": 100, "simulated": True, "network_action_taken": False}


@router.post("/checkpoints", status_code=201)
def create_checkpoint(payload: ReferenceInput, request: Request, db: Session = Depends(database)):
    actor = auditor(request)
    case = db.get(MockInvestigation, payload.investigation_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if actor.subject in (case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Independent auditor required")
    sequence, head = valid_head(db, case.id)
    prior = db.scalar(select(MockCheckpoint).where(
        MockCheckpoint.investigation_id == case.id,
        MockCheckpoint.sequence == sequence))
    if prior is not None:
        if prior.head_digest != head:
            raise HTTPException(status_code=409, detail="Checkpoint differs from ledger")
        return checkpoint_view(prior)
    row = MockCheckpoint(
        id=str(uuid.uuid4()), investigation_id=case.id,
        sequence=sequence, head_digest=head,
        reason_reference=payload.reason_reference,
        checkpoint_digest=checkpoint_hash(case.id, sequence, head, payload.reason_reference),
        recorded_by=actor.subject)
    try:
        db.add(row)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent checkpoint conflict") from None
    return checkpoint_view(row)


def checkpoint_view(row: MockCheckpoint):
    return {"id": row.id, "investigation_id": row.investigation_id,
            "sequence": row.sequence, "head_digest": row.head_digest,
            "reason_reference": row.reason_reference,
            "checkpoint_digest": row.checkpoint_digest,
            "recorded_by": row.recorded_by, "simulated": True,
            "externally_anchored": False}


@router.get("/checkpoints/{investigation_id}")
def check_checkpoints(investigation_id: str, request: Request,
                      db: Session = Depends(database)):
    auditor(request)
    case = db.get(MockInvestigation, investigation_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    checkpoints = db.scalars(select(MockCheckpoint).where(
        MockCheckpoint.investigation_id == case.id).order_by(MockCheckpoint.sequence)).all()
    try:
        length, head = valid_head(db, case.id)
    except HTTPException:
        return {"valid": False, "checkpoints": len(checkpoints),
                "externally_anchored": False, "simulated": True}
    valid = bool(checkpoints)
    history = db.scalars(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case.id).order_by(ReviewLedger.sequence)).all()
    by_sequence = {e.sequence: e for e in history}
    for point in checkpoints:
        event = by_sequence.get(point.sequence)
        if event is None or point.head_digest != event.digest or point.checkpoint_digest != checkpoint_hash(
                case.id, point.sequence, point.head_digest, point.reason_reference):
            valid = False
            break
    return {"valid": valid, "checkpoints": len(checkpoints),
            "current_sequence": length, "current_head": head,
            "externally_anchored": False, "simulated": True}


@router.post("/holds", status_code=201)
def create_hold(payload: ReferenceInput, request: Request, db: Session = Depends(database)):
    actor = supervisor(request)
    case = db.get(MockInvestigation, payload.investigation_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if actor.subject in (case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Independent supervisor required")
    existing = db.scalar(select(LegalHold).where(LegalHold.investigation_id == case.id))
    if existing:
        raise HTTPException(status_code=409, detail="Retention hold already registered")
    row = LegalHold(id=str(uuid.uuid4()), investigation_id=case.id,
                    reason_reference=payload.reason_reference, created_by=actor.subject)
    try:
        db.add(row)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent retention hold conflict") from None
    return {"id": row.id, "investigation_id": case.id,
            "active": True, "simulated": True, "records_deleted": 0}


@router.get("/holds")
def list_holds(request: Request, db: Session = Depends(database)):
    auditor(request)
    holds = db.scalars(select(LegalHold).where(LegalHold.active.is_(True))
                       .order_by(LegalHold.created_at).limit(100)).all()
    return [{"id": hold.id, "investigation_id": hold.investigation_id,
             "active": hold.active, "reason_reference": hold.reason_reference,
             "simulated": True} for hold in holds]
