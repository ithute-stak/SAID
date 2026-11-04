"""Central-only simulation appeals; no live sanctions or equipment actions."""
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
from said.ceir.quality import MockInvestigation
from said.ceir.governance import append_event, lock_case

router = APIRouter(prefix="/api/v1/ceir/sandbox/appeals", tags=["CEIR sandbox appeals"])
Outcome = Literal["original_review_upheld", "returned_for_further_review"]

class MockAppeal(Base):
    __tablename__ = "ceir_mock_appeals"
    __table_args__ = (UniqueConstraint("investigation_id", name="uq_ceir_appeal_case"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_investigations.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(40), nullable=False, default="pending_supervisor")
    reason_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    submitted_by: Mapped[str] = mapped_column(String(200), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decision_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  default=lambda: datetime.now(timezone.utc))

class AppealInput(BaseModel):
    investigation_id: str = Field(min_length=36, max_length=36)
    reason_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

class AppealDecision(BaseModel):
    outcome: Outcome
    decision_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

def view(row: MockAppeal) -> dict:
    return {"id": row.id, "investigation_id": row.investigation_id,
            "state": row.state, "reason_reference": row.reason_reference,
            "submitted_by": row.submitted_by, "reviewed_by": row.reviewed_by,
            "decision_reference": row.decision_reference,
            "simulated": True, "network_action_taken": False}

@router.post("", status_code=201)
def submit(payload: AppealInput, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if "ceir_appeals_officer" not in actor.roles:
        raise HTTPException(status_code=403, detail="Appeals officer role required")
    case = lock_case(db, payload.investigation_id)
    if case.reviewer_reference is None or case.status == "pending_human_review":
        raise HTTPException(status_code=409, detail="Case must have an independent review first")
    if actor.subject in (case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Appeals officer must be independent")
    existing = db.scalar(select(MockAppeal).where(MockAppeal.investigation_id == case.id))
    if existing:
        raise HTTPException(status_code=409, detail="Appeal already exists")
    row = MockAppeal(id=str(uuid.uuid4()), investigation_id=case.id,
                     reason_reference=payload.reason_reference,
                     submitted_by=actor.subject)
    try:
        db.add(row)
        db.flush()
        append_event(db, case.id, "appeal_opened", actor.subject, payload.reason_reference)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Appeal conflict") from None
    return view(row)

@router.get("")
def queue(request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if not (actor.roles & {"ceir_appeals_officer", "ceir_supervisor", "ceir_auditor"}):
        raise HTTPException(status_code=403, detail="Appeals staff role required")
    rows = db.scalars(select(MockAppeal).order_by(MockAppeal.created_at, MockAppeal.id).limit(100)).all()
    return [view(r) for r in rows]

@router.get("/{appeal_id}")
def get_appeal(appeal_id: str, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if not (actor.roles & {"ceir_appeals_officer", "ceir_supervisor"}):
        raise HTTPException(status_code=403, detail="Appeals staff role required")
    row = db.get(MockAppeal, appeal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Appeal not found")
    return view(row)

@router.post("/{appeal_id}/decide")
def decide(appeal_id: str, payload: AppealDecision, request: Request,
           db: Session = Depends(database)):
    actor = require_central(request)
    if "ceir_supervisor" not in actor.roles:
        raise HTTPException(status_code=403, detail="Supervisor role required")
    row = db.get(MockAppeal, appeal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Appeal not found")
    case = lock_case(db, row.investigation_id)
    db.refresh(row)
    if actor.subject in (row.submitted_by, case.opened_by, case.reviewer_reference):
        raise HTTPException(status_code=403, detail="Independent supervisor required")
    result = db.execute(update(MockAppeal)
        .where(MockAppeal.id == appeal_id, MockAppeal.state == "pending_supervisor")
        .values(state=payload.outcome, reviewed_by=actor.subject,
                decision_reference=payload.decision_reference))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Appeal already decided")
    append_event(db, row.investigation_id, "appeal_" + payload.outcome,
                 actor.subject, payload.decision_reference)
    db.commit()
    return view(db.get(MockAppeal, appeal_id))
