"""Phase 18: local checkpoint export manifest and non-destructive retention approvals.

No external audit delivery, crypto signing, personal-data exports, automated
purges, or carrier integrations. All decisions relate to offline mock CEIR.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.ceir.api import require_central
from said.ceir.appeals import MockAppeal
from said.ceir.quality import MockInvestigation
from said.ceir.governance import append_event, lock_case, commit_case
from said.ceir.oversight import LegalHold, MockCheckpoint, valid_head

router = APIRouter(prefix="/api/v1/ceir/sandbox/assurance",
                   tags=["SAID CEIR simulated assurance"])

class RetentionApproval(Base):
    __tablename__ = "ceir_mock_retention_approvals"
    __table_args__ = (UniqueConstraint("investigation_id", name="uq_ceir_retention_approval_case"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_investigations.id"),
                                                 nullable=False)
    rationale_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    approval_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False,
                                        default="pending_independent_approval")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 default=lambda: datetime.now(timezone.utc))

class RequestApproval(BaseModel):
    investigation_id: str = Field(min_length=36, max_length=36)
    rationale_reference: str = Field(min_length=3, max_length=120,
                                     pattern=r"^[A-Za-z0-9_-]+$")

class DecideApproval(BaseModel):
    decision: Literal["approve_plan", "reject_plan"]
    approval_reference: str = Field(min_length=3, max_length=120,
                                    pattern=r"^[A-Za-z0-9_-]+$")

def require_role(request: Request, role: str):
    actor = require_central(request)
    if role not in actor.roles:
        raise HTTPException(status_code=403, detail="Independent assurance permission required")
    if actor.subject == "development-admin":
        raise HTTPException(status_code=403, detail="Verified institutional subject required")
    return actor

def ensure_case_eligible(db: Session, case: MockInvestigation):
    if not case.opened_by or not case.reviewer_reference or case.status == "pending_human_review":
        raise HTTPException(status_code=409, detail="Independent review not completed")
    hold = db.scalar(select(LegalHold.id).where(
        LegalHold.investigation_id == case.id, LegalHold.active.is_(True)))
    appeal = db.scalar(select(MockAppeal.id).where(
        MockAppeal.investigation_id == case.id,
        MockAppeal.state.in_(("pending_supervisor", "returned_for_further_review"))))
    if hold or appeal:
        raise HTTPException(status_code=409, detail="Preservation hold or appeal prevents retention approval")

def approval_view(row: RetentionApproval):
    return {"id": row.id, "investigation_id": row.investigation_id,
            "status": row.status, "rationale_reference": row.rationale_reference,
            "requested_by": row.requested_by, "approved_by": row.approved_by,
            "approval_reference": row.approval_reference, "simulated": True,
            "execution_enabled": False, "records_deleted": 0}

@router.post("/retention-plans", status_code=201)
def create_plan(payload: RequestApproval, request: Request, db: Session = Depends(database)):
    actor = require_role(request, "ceir_supervisor")
    case = lock_case(db, payload.investigation_id)
    if actor.subject in (case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Independent supervisor required")
    ensure_case_eligible(db, case)
    if db.scalar(select(RetentionApproval.id).where(
            RetentionApproval.investigation_id == case.id)):
        raise HTTPException(status_code=409, detail="Retention plan already exists")
    row = RetentionApproval(id=str(uuid.uuid4()), investigation_id=case.id,
                            rationale_reference=payload.rationale_reference,
                            requested_by=actor.subject)
    try:
        db.add(row)
        db.flush()
        append_event(db, case.id, "retention_plan_requested", actor.subject,
                     payload.rationale_reference)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent retention plan conflict") from None
    return approval_view(row)

@router.get("/retention-plans")
def list_plans(request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if not (actor.roles & {"ceir_supervisor", "ceir_retention_approver", "ceir_auditor"}):
        raise HTTPException(status_code=403, detail="Assurance permission required")
    rows = db.scalars(select(RetentionApproval).order_by(
        RetentionApproval.created_at, RetentionApproval.id).limit(100)).all()
    return [approval_view(row) for row in rows]

@router.post("/retention-plans/{plan_id}/decide")
def decide_plan(plan_id: str, payload: DecideApproval, request: Request,
                db: Session = Depends(database)):
    actor = require_role(request, "ceir_retention_approver")
    row = db.get(RetentionApproval, plan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Retention plan not found")
    case = lock_case(db, row.investigation_id)
    db.refresh(row)
    if actor.subject in (case.opened_by, case.reviewer_reference, row.requested_by):
        raise HTTPException(status_code=403, detail="Independent retention approver required")
    ensure_case_eligible(db, case)
    new_state = ("approved_plan_only" if payload.decision == "approve_plan" else
                 "rejected_plan")
    updated = db.execute(update(RetentionApproval).where(
        RetentionApproval.id == row.id,
        RetentionApproval.status == "pending_independent_approval").values(
            status=new_state, approved_by=actor.subject,
            approval_reference=payload.approval_reference))
    if updated.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Retention plan already decided")
    append_event(db, case.id, "retention_" + new_state,
                 actor.subject, payload.approval_reference)
    db.commit()
    return approval_view(db.get(RetentionApproval, plan_id))

@router.get("/checkpoints/{checkpoint_id}/manifest")
def checkpoint_manifest(checkpoint_id: str, request: Request, db: Session = Depends(database)):
    actor = require_role(request, "ceir_auditor")
    row = db.get(MockCheckpoint, checkpoint_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Audit checkpoint not found")
    case = lock_case(db, row.investigation_id)
    db.refresh(row)
    if actor.subject in (case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Independent auditor required")
    length, _ = valid_head(db, case.id)
    if row.sequence > length:
        raise HTTPException(status_code=409, detail="Checkpoint sequence not in ledger")
    from said.ceir.governance import ReviewLedger, digest_of
    from said.ceir.oversight import checkpoint_hash
    event = db.scalar(select(ReviewLedger).where(
        ReviewLedger.investigation_id == case.id, ReviewLedger.sequence == row.sequence))
    if (event is None or event.digest != row.head_digest or
            row.checkpoint_digest != checkpoint_hash(
                case.id, row.sequence, row.head_digest, row.reason_reference)):
        raise HTTPException(status_code=409, detail="Local checkpoint integrity conflict")
    document = {
        "schema": "said.mock.audit-checkpoint.v1", "checkpoint_id": row.id,
        "investigation_id": row.investigation_id, "sequence": row.sequence,
        "head_digest": row.head_digest, "checkpoint_digest": row.checkpoint_digest,
        "reason_reference": row.reason_reference,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return {"manifest": document, "manifest_sha256": hashlib.sha256(
        canonical.encode("utf-8")).hexdigest(),
        "export_preparation_only": True, "externally_anchored": False,
        "signed": False, "transmitted": False, "simulated": True}
