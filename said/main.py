"""Phase 1 admin-only foundation. Real citizen auth and operator connectors are NOT active."""
import os
import re
import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from said.security import current_principal, Principal
from said.authorization import require_role, require_institution, registration_institution
import said.rls  # transaction-scoped PostgreSQL RLS identity context

DATABASE_URL = os.getenv("SAID_DATABASE_URL", "sqlite:///./said.db")
ADMIN_KEY = os.getenv("SAID_ADMIN_API_KEY", "")
if os.getenv("SAID_ENVIRONMENT", "development").lower() in {"development", "test"} and (len(ADMIN_KEY) < 32 or ADMIN_KEY.startswith("REPLACE_")):
    raise RuntimeError("SAID_ADMIN_API_KEY must be a configured secret of at least 32 characters in development")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    imei: Mapped[str] = mapped_column(String(15), unique=True, nullable=False, index=True)
    owner_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    institution_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    make: Mapped[str] = mapped_column(String(80), nullable=False)
    model: Mapped[str] = mapped_column(String(80), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(40), default="unverified", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    reports: Mapped[list["TheftReport"]] = relationship(back_populates="device")

class TheftReport(Base):
    __tablename__ = "theft_reports"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False)
    incident_reference: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="reported_pending_review", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    device: Mapped[Device] = relationship(back_populates="reports")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    institution_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

def validate_imei(value: str) -> str:
    if not re.fullmatch(r"[0-9]{15}", value):
        raise ValueError("IMEI must be exactly 15 digits")
    numbers = [int(x) for x in value]
    total = 0
    for index, number in enumerate(numbers):
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    if total % 10 != 0:
        raise ValueError("IMEI check digit invalid")
    return value

class Registration(BaseModel):
    imei: str
    owner_reference: str = Field(min_length=1, max_length=120)
    make: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=80)

class ReportRequest(BaseModel):
    incident_reference: str = Field(min_length=1, max_length=120)

class DeviceResult(BaseModel):
    id: str
    imei_masked: str
    verification_status: str

class ReportResult(BaseModel):
    id: str
    device_id: str
    status: str

def admin_auth(request: Request) -> Principal:
    """Authenticate; each route imposes its own role and record policy."""
    return current_principal(request)

def database(request: Request):
    actor = current_principal(request)
    with SessionLocal() as session:
        session.info['said_principal'] = actor
        yield session

# Versioned Alembic migrations must be applied before starting API workers.
from said.ownership import router as ownership_router
from said.protect import router as protect_router
from said.links import router as links_router
from said.ceir.api import router as ceir_router
from said.ceir.exchange import router as ceir_exchange_router
from said.ceir.quality import router as ceir_quality_router

app = FastAPI(title="SAID Platform API", version="0.12.0",
              description="Admin-only prototype. No identity verification or network blocking.")

app.include_router(ownership_router)
app.include_router(protect_router)
app.include_router(links_router)
app.include_router(ceir_router)
app.include_router(ceir_exchange_router)
app.include_router(ceir_quality_router)

WEB_ROOT = Path(__file__).resolve().parent / "web"
app.mount("/console/static", StaticFiles(directory=WEB_ROOT), name="console-static")

@app.get("/protect/", include_in_schema=False)
def protect_console():
    return FileResponse(WEB_ROOT / "protect.html", media_type="text/html", headers={
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    })

@app.get("/console/", include_in_schema=False)
def console():
    return FileResponse(WEB_ROOT / "index.html", media_type="text/html", headers={
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
    })

@app.get("/health")
def health():
    return {"status": "ok", "service": "said-api"}

@app.post("/api/v1/devices", response_model=DeviceResult, status_code=201, dependencies=[Depends(admin_auth)])
def register(payload: Registration, db: Session = Depends(database), actor: Principal = Depends(admin_auth)):
    require_role(actor, "said_admin", "registrar")
    try:
        imei = validate_imei(payload.imei)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if db.scalar(select(Device).where(Device.imei == imei)):
        raise HTTPException(status_code=409, detail="Device IMEI already registered")
    device = Device(id=str(uuid.uuid4()), imei=imei,
                    owner_reference=payload.owner_reference, institution_id=registration_institution(actor),
                    make=payload.make, model=payload.model)
    db.add(device)
    db.add(AuditEvent(id=str(uuid.uuid4()), action="device.registered_unverified", entity_type="device", entity_id=device.id,
                      actor_reference=actor.subject, institution_id=registration_institution(actor)))
    db.commit()
    return DeviceResult(id=device.id, imei_masked="***********" + imei[-4:], verification_status=device.verification_status)

@app.get("/api/v1/devices/{device_id}", response_model=DeviceResult, dependencies=[Depends(admin_auth)])
def get_device(device_id: str, db: Session = Depends(database), actor: Principal = Depends(admin_auth)):
    require_role(actor, "said_admin", "registrar", "case_worker", "owner_reviewer")
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    require_institution(actor, device.institution_id)
    return DeviceResult(id=device.id, imei_masked="***********" + device.imei[-4:], verification_status=device.verification_status)

@app.post("/api/v1/devices/{device_id}/theft-reports", response_model=ReportResult, status_code=201, dependencies=[Depends(admin_auth)])
def report_theft(device_id: str, payload: ReportRequest, db: Session = Depends(database), actor: Principal = Depends(admin_auth)):
    require_role(actor, "said_admin", "case_worker")
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    require_institution(actor, device.institution_id)
    report = TheftReport(id=str(uuid.uuid4()), device_id=device_id, incident_reference=payload.incident_reference)
    db.add(report)
    db.add(AuditEvent(id=str(uuid.uuid4()), action="theft.reported_pending_review", entity_type="theft_report", entity_id=report.id,
                      actor_reference=actor.subject, institution_id=registration_institution(actor)))
    db.commit()
    return ReportResult(id=report.id, device_id=device_id, status=report.status)

@app.get("/api/v1/theft-reports/{report_id}", response_model=ReportResult, dependencies=[Depends(admin_auth)])
def get_report(report_id: str, db: Session = Depends(database), actor: Principal = Depends(admin_auth)):
    require_role(actor, "said_admin", "case_worker")
    report = db.get(TheftReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    require_institution(actor, report.device.institution_id)
    return ReportResult(id=report.id, device_id=report.device_id, status=report.status)
