"""Citizen self-service intake: NO ownership verification, transfer or blocking.

Citizen records are tied to the authenticated OIDC subject, not a user-entered
National ID, telephone number, IMEI, or owner_reference.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import DateTime, ForeignKey, String, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.security import Principal, current_principal
from said.authorization import require_role

router = APIRouter(prefix="/api/v1/protect", tags=["SAID Protect (prototype)"])

class CitizenRequest(Base):
    __tablename__ = "citizen_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    citizen_subject: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    device_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="pending_manual_review")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                  default=lambda: datetime.now(timezone.utc))

class CitizenIntake(BaseModel):
    category: Literal["device_enrollment_inquiry", "lost_device_inquiry", "ownership_inquiry"]
    # This is an opaque, non-sensitive reference, NOT a National ID, phone
    # number, IMEI, document scan, or proof of ownership.
    device_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]{3,120}$")

    @field_validator("device_reference")
    @classmethod
    def reject_numeric_identifiers(cls, value: str) -> str:
        if value.isdigit():
            raise ValueError("Use a reference you invent, not an IMEI, ID or telephone number")
        return value

class CitizenRequestView(BaseModel):
    id: str
    category: str
    device_reference: str
    status: str

def citizen_actor(request: Request) -> Principal:
    actor = current_principal(request)
    require_role(actor, "citizen")
    if actor.institution != "citizens" or actor.subject == "development-admin":
        raise HTTPException(status_code=403, detail="Citizen account required")
    if not actor.subject or len(actor.subject) > 200:
        raise HTTPException(status_code=403, detail="Invalid citizen subject")
    return actor

def view(row: CitizenRequest) -> CitizenRequestView:
    return CitizenRequestView(id=row.id, category=row.category,
                              device_reference=row.device_reference, status=row.status)

@router.get("/requests", response_model=list[CitizenRequestView])
def my_requests(request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    return [view(x) for x in db.scalars(select(CitizenRequest)
            .where(CitizenRequest.citizen_subject == actor.subject)
            .order_by(CitizenRequest.created_at.desc()).limit(50))]

@router.post("/requests", response_model=CitizenRequestView, status_code=201)
def submit_request(payload: CitizenIntake, request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    row = CitizenRequest(id=str(uuid.uuid4()), citizen_subject=actor.subject,
                         category=payload.category, device_reference=payload.device_reference)
    db.add(row)
    db.commit()
    return view(row)

@router.get("/requests/{request_id}", response_model=CitizenRequestView)
def my_request(request_id: str, request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    row = db.scalar(select(CitizenRequest).where(
        CitizenRequest.id == request_id, CitizenRequest.citizen_subject == actor.subject))
    if row is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return view(row)
