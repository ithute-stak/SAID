"""Central-only simulation entities. Never export as operator EIR instructions."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from said.main import Base

class CEIRSimulation(Base):
    __tablename__ = "ceir_simulations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, unique=True)
    proposed_status: Mapped[str] = mapped_column(String(30), nullable=False, default="unassessed")
    revision: Mapped[int] = mapped_column(nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

class CEIRSimulationEvent(Base):
    __tablename__ = "ceir_simulation_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    simulation_id: Mapped[str] = mapped_column(ForeignKey("ceir_simulations.id"), nullable=False, index=True)
    proposed_status: Mapped[str] = mapped_column(String(30), nullable=False)
    reason_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    actor_reference: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
