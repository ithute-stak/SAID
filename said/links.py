"""Citizen-authorized ownership-link *intent*, not a device entitlement.

No real device association, owner verification or visibility is granted.
A citizen may only consent using their OWN previously submitted ownership
inquiry. An approved legal/identity verification pipeline is a later phase.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.protect import CitizenRequest, citizen_actor

router = APIRouter(prefix="/api/v1/protect/link-intents",
                   tags=["SAID Protect - ownership consent prototype"])

class CitizenLinkIntent(Base):
    __tablename__ = "citizen_link_intents"
    __table_args__ = (UniqueConstraint("inquiry_id", name="uq_link_intent_inquiry"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    citizen_subject: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    inquiry_id: Mapped[str] = mapped_column(ForeignKey("citizen_requests.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="awaiting_independent_verification")
    consent_version: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                default=lambda: datetime.now(timezone.utc))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class LinkIntentInput(BaseModel):
    inquiry_id: str = Field(min_length=36, max_length=36)
    consent: Literal[True]
    consent_version: Literal["SAID-LINK-CONSENT-v1"]

class LinkIntentView(BaseModel):
    id: str
    inquiry_id: str
    status: str
    consent_version: str
    # Importantly: NO device_id, IMEI, owner verification or entitlement.

def view(row: CitizenLinkIntent) -> LinkIntentView:
    return LinkIntentView(id=row.id, inquiry_id=row.inquiry_id,
                          status=row.status, consent_version=row.consent_version)

@router.post("", response_model=LinkIntentView, status_code=201)
def create_intent(payload: LinkIntentInput, request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    inquiry = db.scalar(select(CitizenRequest).where(
        CitizenRequest.id == payload.inquiry_id,
        CitizenRequest.citizen_subject == actor.subject,
        CitizenRequest.category == "ownership_inquiry",
    ))
    if inquiry is None:
        raise HTTPException(status_code=404, detail="Ownership inquiry not found")
    prior = db.scalar(select(CitizenLinkIntent.id).where(CitizenLinkIntent.inquiry_id == inquiry.id))
    if prior:
        raise HTTPException(status_code=409, detail="Consent intent already exists")
    row = CitizenLinkIntent(id=str(uuid.uuid4()), citizen_subject=actor.subject,
                            inquiry_id=inquiry.id, consent_version=payload.consent_version)
    db.add(row)
    db.commit()
    return view(row)

@router.get("", response_model=list[LinkIntentView])
def my_intents(request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    rows = db.scalars(select(CitizenLinkIntent)
                      .where(CitizenLinkIntent.citizen_subject == actor.subject)
                      .order_by(CitizenLinkIntent.created_at.desc()).limit(50)).all()
    return [view(row) for row in rows]

@router.get("/{intent_id}", response_model=LinkIntentView)
def my_intent(intent_id: str, request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    row = db.scalar(select(CitizenLinkIntent).where(
        CitizenLinkIntent.id == intent_id, CitizenLinkIntent.citizen_subject == actor.subject))
    if row is None:
        raise HTTPException(status_code=404, detail="Link intent not found")
    return view(row)

@router.post("/{intent_id}/withdraw", response_model=LinkIntentView)
def withdraw_intent(intent_id: str, request: Request, db: Session = Depends(database)):
    actor = citizen_actor(request)
    changed = db.execute(update(CitizenLinkIntent)
                         .where(CitizenLinkIntent.id == intent_id,
                                CitizenLinkIntent.citizen_subject == actor.subject,
                                CitizenLinkIntent.status == "awaiting_independent_verification")
                         .values(status="withdrawn", withdrawn_at=datetime.now(timezone.utc)))
    if changed.rowcount != 1:
        raise HTTPException(status_code=404, detail="Active link intent not found")
    db.commit()
    row = db.scalar(select(CitizenLinkIntent).where(
        CitizenLinkIntent.id == intent_id, CitizenLinkIntent.citizen_subject == actor.subject))
    return view(row)
