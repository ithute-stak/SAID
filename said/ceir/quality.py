"""Offline CEIR data quality and multi-observation signals.

Only hypothetical mock sources, never carrier feeds. Repeated IMEI observations
are not proof of duplication, cloning, theft or altered IMEI.
"""
import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database, validate_imei
from said.ceir.api import require_central

router = APIRouter(prefix="/api/v1/ceir/sandbox/quality", tags=["CEIR simulated data quality"])
Source = Literal["mock_operator_alpha", "mock_operator_beta"]
Review = Literal["needs_investigation", "insufficient_evidence", "closed_false_positive"]

class MockObservation(Base):
    __tablename__ = "ceir_mock_observations"
    __table_args__ = (UniqueConstraint("source_code", "reference", name="uq_ceir_mock_observation_reference"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    source_code: Mapped[str] = mapped_column(String(40), nullable=False)
    reference: Mapped[str] = mapped_column(String(120), nullable=False)
    imei_token: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

class MockInvestigation(Base):
    __tablename__ = "ceir_mock_investigations"
    __table_args__ = (UniqueConstraint("observation_id", name="uq_ceir_mock_investigation_observation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_observations.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending_human_review")
    opened_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    reviewer_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decision_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)

class ObservationInput(BaseModel):
    source_code: Source
    reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")
    imei: str = Field(min_length=15, max_length=15, pattern=r"^[0-9]{15}$")

class ObservationView(BaseModel):
    id: str
    source_code: str
    reference: str
    valid_imei_checksum: Literal[True] = True
    simulated: Literal[True] = True
    device_identified: Literal[False] = False

class QualityView(BaseModel):
    observation_id: str
    distinct_mock_sources: int
    observations_with_same_imei: int
    indicators: list[str]
    conclusion: Literal["human_review_required"] = "human_review_required"
    changed_imei_detected: Literal[False] = False
    theft_determined: Literal[False] = False
    network_action_taken: Literal[False] = False

class ReviewInput(BaseModel):
    decision: Review
    decision_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

def token(imei: str) -> str:
    secret = os.getenv("SAID_CEIR_HMAC_KEY", "")
    if len(secret) < 32 or secret.startswith("REPLACE_"):
        raise HTTPException(status_code=503, detail="CEIR sandbox key not configured")
    return hmac.new(secret.encode("utf-8"), imei.encode("ascii"), hashlib.sha256).hexdigest()

def obs_view(row: MockObservation) -> ObservationView:
    return ObservationView(id=row.id, source_code=row.source_code, reference=row.reference)

@router.post("/observations", response_model=ObservationView, status_code=201)
def record_observation(payload: ObservationInput, request: Request, db: Session = Depends(database)):
    require_central(request)
    try:
        validate_imei(payload.imei)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    digest = token(payload.imei)
    prior = db.scalar(select(MockObservation).where(
        MockObservation.source_code == payload.source_code, MockObservation.reference == payload.reference))
    if prior is not None:
        if hmac.compare_digest(prior.imei_token, digest):
            return obs_view(prior)
        raise HTTPException(status_code=409, detail="Mock source reference already used")
    row = MockObservation(id=str(uuid.uuid4()), source_code=payload.source_code,
                          reference=payload.reference, imei_token=digest)
    try:
        db.add(row)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent observation conflict") from None
    return obs_view(row)

@router.get("/observations/{observation_id}", response_model=QualityView)
def analyze(observation_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    row = db.get(MockObservation, observation_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    same = db.scalars(select(MockObservation).where(MockObservation.imei_token == row.imei_token)).all()
    sources = len({x.source_code for x in same})
    indicators = []
    if len(same) > 1:
        indicators.append("repeat_mock_imei_observation")
    if sources > 1:
        indicators.append("observed_across_multiple_mock_sources")
    if not indicators:
        indicators.append("no_repeat_observed_in_current_mock_sample")
    return QualityView(observation_id=row.id, distinct_mock_sources=sources,
                       observations_with_same_imei=len(same), indicators=indicators)

@router.post("/observations/{observation_id}/investigation", status_code=201)
def open_investigation(observation_id: str, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if db.get(MockObservation, observation_id) is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    previous = db.scalar(select(MockInvestigation).where(MockInvestigation.observation_id == observation_id))
    if previous is not None:
        return {"id": previous.id, "status": previous.status, "simulated": True}
    row = MockInvestigation(id=str(uuid.uuid4()), observation_id=observation_id,
                            opened_by=actor.subject)
    from said.ceir.governance import append_event
    try:
        db.add(row)
        db.flush()
        append_event(db, row.id, "investigation_opened", actor.subject, "sandbox_opened")
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent investigation conflict") from None
    return {"id": row.id, "status": row.status, "simulated": True}

@router.post("/investigations/{investigation_id}/review")
def review(investigation_id: str, payload: ReviewInput, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if "ceir_reviewer" not in actor.roles:
        raise HTTPException(status_code=403, detail="Independent CEIR reviewer role required")
    from said.ceir.governance import lock_case
    row = lock_case(db, investigation_id)
    if not row.opened_by or actor.subject == row.opened_by:
        raise HTTPException(status_code=403, detail="Independent reviewer required")
    if row.status != "pending_human_review":
        raise HTTPException(status_code=409, detail="Investigation already reviewed")
    # Compare-and-swap permits only one independent reviewer to decide.
    # PostgreSQL row locking serializes competing status transitions.
    changed = db.execute(update(MockInvestigation).where(
        MockInvestigation.id == row.id,
        MockInvestigation.status == "pending_human_review").values(
            status=payload.decision, decision_reference=payload.decision_reference,
            reviewer_reference=actor.subject))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Investigation already reviewed")
    from said.ceir.governance import append_event
    try:
        append_event(db, row.id, "review_" + payload.decision,
                     actor.subject, payload.decision_reference)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent review ledger conflict") from None
    return {"id": row.id, "status": payload.decision, "simulated": True,
            "network_action_taken": False}
