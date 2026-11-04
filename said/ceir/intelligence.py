"""SAID Intelligence: provenance and explainable, immutable sandbox assessments.

No physical-device identification, altered IMEI inference, enforcement,
external data ingestion, carrier communications, or real-world risk scoring.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.ceir.api import require_central
from said.ceir.quality import MockObservation, MockInvestigation

router = APIRouter(prefix="/api/v1/ceir/sandbox/intelligence",
                   tags=["CEIR Intelligence - offline simulation"])

ProvenanceKind = Literal["synthetic_fixture", "mock_feed"]
Confidence = Literal["insufficient_evidence", "corroboration_required"]

class MockProvenance(Base):
    __tablename__ = "ceir_mock_provenance"
    __table_args__ = (UniqueConstraint("observation_id", name="uq_ceir_mock_provenance_observation"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_observations.id"), nullable=False)
    source_code: Mapped[str] = mapped_column(String(40), nullable=False)
    provenance_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    recorded_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                default=lambda: datetime.now(timezone.utc))

class MockAssessment(Base):
    __tablename__ = "ceir_mock_assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_observations.id"), nullable=False, index=True)
    distinct_sources: Mapped[int] = mapped_column(Integer, nullable=False)
    same_imei_count: Mapped[int] = mapped_column(Integer, nullable=False)
    provenance_count: Mapped[int] = mapped_column(Integer, nullable=False)
    conclusion: Mapped[str] = mapped_column(String(40), nullable=False)
    assessed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                default=lambda: datetime.now(timezone.utc))

class ProvenanceInput(BaseModel):
    observation_id: str = Field(min_length=36, max_length=36)
    source_code: Literal["mock_operator_alpha", "mock_operator_beta"]
    provenance_kind: ProvenanceKind
    evidence_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

class AssessmentView(BaseModel):
    id: str
    observation_id: str
    distinct_mock_sources: int
    observations_with_same_imei: int
    documented_provenance: int
    confidence: Confidence
    indicators: list[str]
    simulated: Literal[True] = True
    imei_changed: Literal[False] = False
    theft_determined: Literal[False] = False
    network_action_taken: Literal[False] = False

def assessment_view(row: MockAssessment) -> dict:
    indicators = []
    if row.same_imei_count > 1:
        indicators.append("repeat_mock_imei_observation")
    if row.distinct_sources > 1:
        indicators.append("observed_across_multiple_mock_sources")
    if row.provenance_count < row.same_imei_count:
        indicators.append("incomplete_mock_provenance")
    if not indicators:
        indicators.append("no_repeat_observed_in_current_mock_sample")
    return {
        "id": row.id, "observation_id": row.observation_id,
        "distinct_mock_sources": row.distinct_sources,
        "observations_with_same_imei": row.same_imei_count,
        "documented_provenance": row.provenance_count,
        "confidence": row.conclusion, "indicators": indicators,
        "simulated": True, "imei_changed": False, "theft_determined": False,
        "network_action_taken": False,
    }

@router.post("/provenance", status_code=201)
def record_provenance(payload: ProvenanceInput, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    obs = db.get(MockObservation, payload.observation_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Mock observation not found")
    if obs.source_code != payload.source_code:
        raise HTTPException(status_code=409, detail="Mock source mismatch")
    prior = db.scalar(select(MockProvenance).where(MockProvenance.observation_id == obs.id))
    if prior is not None:
        raise HTTPException(status_code=409, detail="Provenance is already recorded")
    row = MockProvenance(id=str(uuid.uuid4()), observation_id=obs.id,
                         source_code=payload.source_code,
                         provenance_kind=payload.provenance_kind,
                         evidence_reference=payload.evidence_reference,
                         recorded_by=actor.subject)
    try:
        db.add(row)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Provenance conflict") from None
    return {"id": row.id, "observation_id": obs.id, "simulated": True}

@router.get("/observations/{observation_id}/provenance")
def view_provenance(observation_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    if db.get(MockObservation, observation_id) is None:
        raise HTTPException(status_code=404, detail="Mock observation not found")
    row = db.scalar(select(MockProvenance).where(MockProvenance.observation_id == observation_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Provenance not recorded")
    return {"observation_id": row.observation_id, "source_code": row.source_code,
            "provenance_kind": row.provenance_kind, "evidence_reference": row.evidence_reference,
            "recorded_by": row.recorded_by, "simulated": True}

@router.post("/observations/{observation_id}/assessments", status_code=201)
def assess(observation_id: str, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    obs = db.get(MockObservation, observation_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Mock observation not found")
    same = db.scalars(select(MockObservation).where(
        MockObservation.imei_token == obs.imei_token)).all()
    ids = [x.id for x in same]
    documented = db.scalars(select(MockProvenance).where(
        MockProvenance.observation_id.in_(ids))).all()
    distinct = len({x.source_code for x in same})
    # No "high confidence" claim from repeat IMEI alone.
    conclusion = ("corroboration_required" if len(same) > 1
                  else "insufficient_evidence")
    row = MockAssessment(id=str(uuid.uuid4()), observation_id=observation_id,
                         distinct_sources=distinct, same_imei_count=len(same),
                         provenance_count=len(documented), conclusion=conclusion,
                         assessed_by=actor.subject)
    db.add(row)
    db.commit()
    return assessment_view(row)

@router.get("/observations/{observation_id}/assessments")
def history(observation_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    if db.get(MockObservation, observation_id) is None:
        raise HTTPException(status_code=404, detail="Mock observation not found")
    rows = db.scalars(select(MockAssessment).where(
        MockAssessment.observation_id == observation_id).order_by(
            MockAssessment.created_at, MockAssessment.id).limit(100)).all()
    return [assessment_view(x) for x in rows]

@router.get("/investigations")
def investigations(request: Request, db: Session = Depends(database)):
    require_central(request)
    rows = db.scalars(select(MockInvestigation).order_by(MockInvestigation.id).limit(100)).all()
    return [{"id": x.id, "observation_id": x.observation_id, "status": x.status,
             "reviewed": x.reviewer_reference is not None,
             "simulated": True} for x in rows]
