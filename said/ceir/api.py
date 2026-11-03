"""Q.5055-aligned sandbox: no external synchronization or live status mutation."""
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from said.authorization import central_admin
from said.main import Device, database
from said.security import current_principal, Principal
from said.ceir.models import CEIRSimulation, CEIRSimulationEvent

router = APIRouter(prefix="/api/v1/ceir/sandbox", tags=["CEIR sandbox (not operational)"])
Proposal = Literal["proposed_permitted", "proposed_tracked", "proposed_blocked"]

def require_central(request: Request) -> Principal:
    actor = current_principal(request)
    if not central_admin(actor):
        raise HTTPException(status_code=403, detail="Central SAID authorization required")
    return actor

class CreateSimulation(BaseModel):
    device_id: str = Field(min_length=36, max_length=36)

class ProposeStatus(BaseModel):
    proposed_status: Proposal
    reason_reference: str = Field(min_length=3, max_length=120, pattern=r"^[a-zA-Z0-9_-]{3,120}$")
    expected_revision: int = Field(ge=1)

class SimulationView(BaseModel):
    id: str
    device_id: str
    proposed_status: str
    revision: int
    sandbox_only: Literal[True] = True
    network_action_taken: Literal[False] = False

def view(row: CEIRSimulation) -> SimulationView:
    return SimulationView(id=row.id, device_id=row.device_id,
                          proposed_status=row.proposed_status, revision=row.revision)

@router.post("/entries", response_model=SimulationView, status_code=201)
def create_entry(payload: CreateSimulation, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if db.get(Device, payload.device_id) is None:
        raise HTTPException(status_code=404, detail="Device not found")
    row = CEIRSimulation(id=str(uuid.uuid4()), device_id=payload.device_id)
    db.add(row)
    db.flush()
    db.add(CEIRSimulationEvent(id=str(uuid.uuid4()), simulation_id=row.id,
                               proposed_status="unassessed", reason_reference="sandbox_created",
                               actor_reference=actor.subject))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Sandbox entry already exists") from None
    return view(row)

@router.get("/entries/{entry_id}", response_model=SimulationView)
def get_entry(entry_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    row = db.get(CEIRSimulation, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Sandbox entry not found")
    return view(row)

@router.post("/entries/{entry_id}/propose", response_model=SimulationView)
def propose(entry_id: str, payload: ProposeStatus, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    result = db.execute(update(CEIRSimulation)
                        .where(CEIRSimulation.id == entry_id,
                               CEIRSimulation.revision == payload.expected_revision)
                        .values(proposed_status=payload.proposed_status,
                                revision=CEIRSimulation.revision + 1))
    if result.rowcount != 1:
        raise HTTPException(status_code=409, detail="Entry missing or revision conflict")
    db.add(CEIRSimulationEvent(id=str(uuid.uuid4()), simulation_id=entry_id,
                               proposed_status=payload.proposed_status,
                               reason_reference=payload.reason_reference,
                               actor_reference=actor.subject))
    db.commit()
    return view(db.get(CEIRSimulation, entry_id))

@router.get("/entries/{entry_id}/events")
def events(entry_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    if db.get(CEIRSimulation, entry_id) is None:
        raise HTTPException(status_code=404, detail="Sandbox entry not found")
    rows = db.scalars(select(CEIRSimulationEvent)
                      .where(CEIRSimulationEvent.simulation_id == entry_id)
                      .order_by(CEIRSimulationEvent.created_at, CEIRSimulationEvent.id)).all()
    return [{"proposed_status": x.proposed_status, "reason_reference": x.reason_reference,
             "actor_reference": x.actor_reference} for x in rows]
