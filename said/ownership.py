"""Admin-only, evidence-review prototype: never represents a verified National ID."""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import AuditEvent, Base, Device, database
from said.security import current_principal
from said.authorization import require_role, require_institution

router = APIRouter(prefix="/api/v1/ownership", tags=["ownership-prototype"])

class OwnershipClaim(Base):
    __tablename__ = "ownership_claims"
    __table_args__ = (UniqueConstraint("device_id", name="uq_one_ownership_claim_per_device_phase2"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    applicant_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending_review")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

class ClaimInput(BaseModel):
    device_id: str
    applicant_reference: str = Field(min_length=1, max_length=120)
    evidence_reference: str = Field(min_length=1, max_length=120)

class ReviewInput(BaseModel):
    decision: Literal["evidence_supported", "evidence_rejected"]

class ClaimResult(BaseModel):
    id: str
    device_id: str
    status: str
    identity_verified: bool = False

def claim_device_institution(db: Session, claim: OwnershipClaim) -> str | None:
    device = db.get(Device, claim.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return device.institution_id

def result(c: OwnershipClaim) -> ClaimResult:
    return ClaimResult(id=c.id, device_id=c.device_id, status=c.status,
                       identity_verified=False)

@router.post("/claims", response_model=ClaimResult, status_code=201)
def create_claim(payload: ClaimInput, request: Request, db: Session = Depends(database)):
    actor = current_principal(request)
    require_role(actor, "said_admin", "registrar")
    device = db.get(Device, payload.device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")
    require_institution(actor, device.institution_id)
    if db.scalar(select(OwnershipClaim.id).where(OwnershipClaim.device_id == payload.device_id)):
        raise HTTPException(status_code=409, detail="Existing claim requires separate dispute or appeal workflow")
    claim = OwnershipClaim(id=str(uuid.uuid4()), device_id=payload.device_id,
                           applicant_reference=payload.applicant_reference,
                           evidence_reference=payload.evidence_reference)
    db.add(claim)
    db.add(AuditEvent(id=str(uuid.uuid4()), action="ownership.claim_submitted",
                      entity_type="ownership_claim", entity_id=claim.id,
                      actor_reference=actor.subject))
    db.commit()
    return result(claim)

@router.get("/claims/{claim_id}", response_model=ClaimResult)
def fetch_claim(claim_id: str, request: Request, db: Session = Depends(database)):
    actor = current_principal(request)
    require_role(actor, "said_admin", "owner_reviewer", "registrar")
    claim = db.get(OwnershipClaim, claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Ownership claim not found")
    require_institution(actor, claim_device_institution(db, claim))
    return result(claim)

@router.post("/claims/{claim_id}/review", response_model=ClaimResult)
def review_claim(claim_id: str, payload: ReviewInput, request: Request, db: Session = Depends(database)):
    actor = current_principal(request)
    require_role(actor, "said_admin", "owner_reviewer")
    claim = db.get(OwnershipClaim, claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Ownership claim not found")
    require_institution(actor, claim_device_institution(db, claim))
    if claim.status != "pending_review":
        raise HTTPException(status_code=409, detail="Claim already reviewed")
    claim.status = payload.decision
    claim.reviewed_at = datetime.now(timezone.utc)
    claim.reviewed_by = actor.subject
    db.add(AuditEvent(id=str(uuid.uuid4()), action="ownership." + payload.decision,
                      entity_type="ownership_claim", entity_id=claim.id,
                      actor_reference=actor.subject))
    # Review of supplied evidence never marks the National ID or ownership as verified.
    db.commit()
    return result(claim)
