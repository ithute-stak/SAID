"""Isolated mock CEIR–EIR exchange: NO real operator communications.

Three delivery modes model ITU-T Q Suppl. 76 options. All payloads are
simulation IDs and proposed statuses, not actual IMEI or EIR commands.
"""
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from said.main import Base, database
from said.ceir.api import require_central
from said.ceir.models import CEIRSimulation

router = APIRouter(prefix="/api/v1/ceir/sandbox/exchange", tags=["CEIR EIR exchange simulator"])
Mode = Literal["sync_api", "async_api", "periodic_file"]
Operator = Literal["mock_operator_alpha", "mock_operator_beta"]
DeliveryState = Literal["queued", "awaiting_mock_ack", "acknowledged", "retry_pending"]

class MockExchange(Base):
    __tablename__ = "ceir_mock_exchanges"
    __table_args__ = (
        UniqueConstraint("operator_code", "simulation_id", "revision", "mode",
                         name="uq_mock_exchange_delivery"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    operator_code: Mapped[str] = mapped_column(String(40), nullable=False)
    simulation_id: Mapped[str] = mapped_column(ForeignKey("ceir_simulations.id"), nullable=False, index=True)
    revision: Mapped[int] = mapped_column(Integer(), nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    proposed_status: Mapped[str] = mapped_column(String(30), nullable=False)
    state: Mapped[str] = mapped_column(String(35), nullable=False, default="queued")
    attempt_count: Mapped[int] = mapped_column(Integer(), nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 default=lambda: datetime.now(timezone.utc))

class MockExchangeEvent(Base):
    __tablename__ = "ceir_mock_exchange_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    exchange_id: Mapped[str] = mapped_column(ForeignKey("ceir_mock_exchanges.id"), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 default=lambda: datetime.now(timezone.utc))

class QueueInput(BaseModel):
    simulation_id: str = Field(min_length=36, max_length=36)
    operator_code: Operator
    mode: Mode

class AttemptInput(BaseModel):
    # Explicit fault injection for offline tests; NO URLs, files or client transports.
    simulate_failure: bool = False

class ExchangeView(BaseModel):
    id: str
    operator_code: str
    simulation_id: str
    revision: int
    mode: str
    proposed_status: str
    state: str
    attempt_count: int
    simulated: Literal[True] = True
    external_transmission: Literal[False] = False
    network_action_taken: Literal[False] = False

def view(row: MockExchange) -> ExchangeView:
    return ExchangeView(id=row.id, operator_code=row.operator_code,
                        simulation_id=row.simulation_id, revision=row.revision,
                        mode=row.mode, proposed_status=row.proposed_status,
                        state=row.state, attempt_count=row.attempt_count)

def log(db: Session, exchange_id: str, action: str, subject: str):
    db.add(MockExchangeEvent(id=str(uuid.uuid4()), exchange_id=exchange_id,
                             action=action, actor_reference=subject))

@router.post("/queue", response_model=ExchangeView, status_code=201)
def queue(payload: QueueInput, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    sim = db.get(CEIRSimulation, payload.simulation_id)
    if sim is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    if sim.proposed_status == "unassessed":
        raise HTTPException(status_code=409, detail="Simulation has no proposed status")
    existing = db.scalar(select(MockExchange).where(
        MockExchange.operator_code == payload.operator_code,
        MockExchange.simulation_id == sim.id,
        MockExchange.revision == sim.revision,
        MockExchange.mode == payload.mode))
    if existing is not None:
        return view(existing)  # safe idempotent replay; no second delivery
    row = MockExchange(id=str(uuid.uuid4()), operator_code=payload.operator_code,
                       simulation_id=sim.id, revision=sim.revision,
                       mode=payload.mode, proposed_status=sim.proposed_status)
    try:
        db.add(row)
        db.flush()
        log(db, row.id, "enqueued", actor.subject)
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(MockExchange).where(
            MockExchange.operator_code == payload.operator_code,
            MockExchange.simulation_id == sim.id,
            MockExchange.revision == sim.revision, MockExchange.mode == payload.mode))
        if existing is None:
            raise HTTPException(status_code=409, detail="Exchange conflict") from None
        return view(existing)
    return view(row)

@router.get("/{exchange_id}", response_model=ExchangeView)
def get_exchange(exchange_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    row = db.get(MockExchange, exchange_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exchange not found")
    return view(row)

@router.post("/{exchange_id}/attempt", response_model=ExchangeView)
def attempt(exchange_id: str, payload: AttemptInput, request: Request,
            db: Session = Depends(database)):
    actor = require_central(request)
    row = db.get(MockExchange, exchange_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exchange not found")
    if row.state not in ("queued", "retry_pending"):
        raise HTTPException(status_code=409, detail="Exchange not eligible for another attempt")
    # Atomic state transition: prevents double processing on competing workers.
    next_state = ("retry_pending" if payload.simulate_failure else
                  "acknowledged" if row.mode == "sync_api" else "awaiting_mock_ack")
    result = db.execute(update(MockExchange).where(
        MockExchange.id == exchange_id,
        MockExchange.state == row.state,
        MockExchange.attempt_count == row.attempt_count,
    ).values(state=next_state, attempt_count=MockExchange.attempt_count + 1))
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent mock attempt")
    log(db, exchange_id, "simulated_failure" if payload.simulate_failure else
        "simulated_sync_ack" if row.mode == "sync_api" else "simulated_dispatch", actor.subject)
    db.commit()
    return view(db.get(MockExchange, exchange_id))

@router.post("/{exchange_id}/ack", response_model=ExchangeView)
def acknowledge(exchange_id: str, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    row = db.get(MockExchange, exchange_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Exchange not found")
    if row.mode == "sync_api" or row.state != "awaiting_mock_ack":
        raise HTTPException(status_code=409, detail="Mock acknowledgement not expected")
    changed = db.execute(update(MockExchange).where(
        MockExchange.id == exchange_id, MockExchange.state == "awaiting_mock_ack"
    ).values(state="acknowledged"))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Acknowledgement already processed")
    log(db, exchange_id, "simulated_ack", actor.subject)
    db.commit()
    return view(db.get(MockExchange, exchange_id))

@router.get("/{exchange_id}/events")
def exchange_events(exchange_id: str, request: Request, db: Session = Depends(database)):
    require_central(request)
    if db.get(MockExchange, exchange_id) is None:
        raise HTTPException(status_code=404, detail="Exchange not found")
    rows = db.scalars(select(MockExchangeEvent).where(
        MockExchangeEvent.exchange_id == exchange_id).order_by(
            MockExchangeEvent.created_at, MockExchangeEvent.id)).all()
    return [{"action": row.action, "actor_reference": row.actor_reference} for row in rows]

@router.get("/reconcile/{operator_code}")
def reconcile(operator_code: Operator, request: Request, db: Session = Depends(database)):
    require_central(request)
    # Sandbox-only comparison against latest simulated proposed revision.
    entries = db.scalars(select(CEIRSimulation)).all()
    exchanges = db.scalars(select(MockExchange).where(
        MockExchange.operator_code == operator_code)).all()
    latest = {(x.simulation_id, x.revision): x for x in exchanges if x.state == "acknowledged"}
    missing = [{"simulation_id": x.id, "revision": x.revision}
               for x in entries if x.proposed_status != "unassessed"
               and (x.id, x.revision) not in latest]
    return {"operator_code": operator_code, "simulated": True,
            "network_action_taken": False, "pending_revisions": missing}
