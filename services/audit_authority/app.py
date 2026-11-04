"""Separate mock audit signer, not imported or mounted by the SAID application.

No operator network access, SAID database access, or automated exchange.
This standalone ASGI service requires its own isolated runtime and data store.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title="SAID Independent Mock Audit Authority",
              version="0.1.0", description="Offline sandbox; NOT a real audit authority")

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema: Literal["said.mock.audit-checkpoint.v1"]
    checkpoint_id: str = Field(min_length=36, max_length=36)
    investigation_id: str = Field(min_length=36, max_length=36)
    sequence: int = Field(ge=1)
    head_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manifest: Manifest
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def settings():
    # Prevent running this demonstration service accidentally in production.
    if os.getenv("SAID_AUDIT_SANDBOX_ENABLED") != "true" or os.getenv(
            "SAID_ENVIRONMENT", "development").lower() not in ("development", "test"):
        raise HTTPException(status_code=503, detail="Offline audit sandbox is disabled")
    token = os.getenv("SAID_AUDIT_AUTHORITY_TOKEN", "")
    name = os.getenv("SAID_AUDIT_AUTHORITY_KEY_ID", "")
    db_path = os.getenv("SAID_AUDIT_AUTHORITY_DB_PATH", "")
    key_path = os.getenv("SAID_AUDIT_AUTHORITY_KEY_PATH", "")
    if (len(token) < 32 or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", name)
            or not db_path or not key_path):
        raise HTTPException(status_code=503, detail="Audit authority configuration missing")
    return token, name, db_path, key_path

def authorize(x_audit_authority_token: str | None):
    expected, name, db_path, key_path = settings()
    if not x_audit_authority_token or not hmac.compare_digest(
            x_audit_authority_token, expected):
        raise HTTPException(status_code=401, detail="Audit authority token required")
    return name, db_path, key_path

@contextmanager
def storage(path):
    with sqlite3.connect(path, timeout=10, isolation_level=None) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("""CREATE TABLE IF NOT EXISTS receipts (
            id TEXT PRIMARY KEY,
            manifest_sha256 TEXT NOT NULL UNIQUE,
            receipt_json TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL
        )""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS receipts_no_update
            BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT,'receipt immutable'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS receipts_no_delete
            BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT,'receipt immutable'); END""")
        yield db

def load_private_key(path):
    # No default key; the authority alone reads this separately provisioned file.
    key_file = Path(path)
    try:
        if key_file.stat().st_mode & 0o077:
            raise ValueError("Private key permissions must be owner-only")
        raw = key_file.read_bytes()
        if len(raw) != 32:
            raise ValueError("Expected 32 raw Ed25519 private key bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (OSError, ValueError):
        raise HTTPException(status_code=503, detail="Audit signer unavailable") from None

@app.post("/v1/mock/receipts", status_code=201)
def issue(request: IssueRequest, x_audit_authority_token: str | None = Header(default=None)):
    key_id, db_path, key_path = authorize(x_audit_authority_token)
    manifest = request.manifest.model_dump()
    actual = hashlib.sha256(canonical(manifest)).hexdigest()
    if not hmac.compare_digest(actual, request.manifest_sha256):
        raise HTTPException(status_code=422, detail="Manifest SHA-256 mismatch")
    key = load_private_key(key_path)
    with storage(db_path) as db:
        # A unique manifest gets precisely one signature/timestamp; replay is idempotent.
        db.execute("BEGIN IMMEDIATE")
        old = db.execute("SELECT receipt_json FROM receipts WHERE manifest_sha256=?",
                         (actual,)).fetchone()
        if old:
            db.commit()
            return {"receipt": json.loads(old[0]), "simulated": True,
                    "externally_anchored": False, "transmitted": False}
        body = {
            "version": "said.mock.receipt.v1", "key_id": key_id,
            "manifest": manifest, "manifest_sha256": actual,
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        signature = base64.b64encode(key.sign(canonical(body))).decode("ascii")
        receipt = {**body, "signature_b64": signature}
        encoded = canonical(receipt).decode("ascii")
        db.execute("INSERT INTO receipts (id,manifest_sha256,receipt_json,receipt_sha256) "
                   "VALUES (?,?,?,?)",
                   (str(uuid.uuid4()), actual, encoded,
                    hashlib.sha256(encoded.encode("ascii")).hexdigest()))
        db.commit()
    return {"receipt": receipt, "simulated": True,
            "externally_anchored": False, "transmitted": False}

@app.get("/v1/mock/receipts/by-manifest/{manifest_sha256}")
def retrieve(manifest_sha256: str, x_audit_authority_token: str | None = Header(default=None)):
    _, db_path, _ = authorize(x_audit_authority_token)
    if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256):
        raise HTTPException(status_code=422, detail="Invalid manifest hash")
    with storage(db_path) as db:
        row = db.execute("SELECT receipt_json,receipt_sha256 FROM receipts "
                         "WHERE manifest_sha256=?", (manifest_sha256,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Receipt not found")
    if hashlib.sha256(row[0].encode("ascii")).hexdigest() != row[1]:
        raise HTTPException(status_code=409, detail="Stored receipt integrity conflict")
    return {"receipt": json.loads(row[0]), "simulated": True,
            "externally_anchored": False, "transmitted": False}

@app.get("/health")
def health():
    return {"service": "said-audit-authority-sandbox", "status": "sandbox-only"}
