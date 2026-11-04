"""Standalone, offline Ed25519 audit receipt verifier.

SAID does NOT sign receipts and does NOT possess the issuer's private key.
Pinned public keys must be provided by an independently governed verifier.
"""
import base64
import binascii
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from said.ceir.api import require_central
from said.main import database

router = APIRouter(prefix="/api/v1/ceir/sandbox/verification",
                   tags=["Offline CEIR audit receipt verification"])

KEY_ID = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-fA-F-]{36}$")

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema: str = Field(pattern=r"^said\.mock\.audit-checkpoint\.v1$")
    checkpoint_id: str = Field(min_length=36, max_length=36)
    investigation_id: str = Field(min_length=36, max_length=36)
    sequence: int = Field(ge=1)
    head_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

class SignedReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(pattern=r"^said.mock.receipt.v1$")
    key_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    manifest: Manifest
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: str = Field(min_length=20, max_length=40)
    signature_b64: str = Field(min_length=86, max_length=100)

def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def signing_bytes(receipt: SignedReceipt) -> bytes:
    return canonical_bytes({
        "version": receipt.version,
        "key_id": receipt.key_id,
        "manifest": receipt.manifest.model_dump(),
        "manifest_sha256": receipt.manifest_sha256,
        "issued_at": receipt.issued_at,
    })

def pinned_keys() -> dict[str, Ed25519PublicKey]:
    """Load only public keys from deployment, never a private signing key."""
    raw = os.getenv("SAID_AUDIT_PUBLIC_KEYS_JSON", "")
    if not raw:
        raise HTTPException(status_code=503, detail="Audit trust store not configured")
    try:
        mapping = json.loads(raw)
        if not isinstance(mapping, dict) or not mapping or len(mapping) > 20:
            raise ValueError("Expected nonempty key map")
        keys = {}
        for kid, b64 in mapping.items():
            if not isinstance(kid, str) or not KEY_ID.fullmatch(kid) or not isinstance(b64, str):
                raise ValueError("Invalid key declaration")
            decoded = base64.b64decode(b64, validate=True)
            if len(decoded) != 32:
                raise ValueError("Ed25519 key must contain 32 bytes")
            keys[kid] = Ed25519PublicKey.from_public_bytes(decoded)
        return keys
    except (ValueError, TypeError, binascii.Error):
        raise HTTPException(status_code=503, detail="Audit trust store invalid") from None

def verify_receipt(receipt: SignedReceipt, trusted: dict[str, Ed25519PublicKey]) -> dict:
    expected = hashlib.sha256(canonical_bytes(receipt.manifest.model_dump())).hexdigest()
    if expected != receipt.manifest_sha256:
        return {"valid": False, "reason": "manifest_digest_mismatch"}
    key = trusted.get(receipt.key_id)
    if key is None:
        return {"valid": False, "reason": "untrusted_key"}
    try:
        issued = datetime.fromisoformat(receipt.issued_at.replace("Z", "+00:00"))
    except ValueError:
        return {"valid": False, "reason": "invalid_issued_at"}
    if issued.tzinfo is None:
        return {"valid": False, "reason": "missing_timezone"}
    now = datetime.now(timezone.utc)
    if issued > now + timedelta(minutes=5):
        return {"valid": False, "reason": "future_issued_at"}
    if issued < now - timedelta(days=365):
        return {"valid": False, "reason": "receipt_outside_test_window"}
    try:
        signature = base64.b64decode(receipt.signature_b64, validate=True)
        if len(signature) != 64:
            raise ValueError("Wrong signature size")
        key.verify(signature, signing_bytes(receipt))
    except (InvalidSignature, ValueError, binascii.Error):
        return {"valid": False, "reason": "invalid_signature"}
    return {"valid": True, "reason": "signature_valid"}

@router.post("/receipts/verify")
def verify(receipt: SignedReceipt, request: Request, db: Session = Depends(database)):
    actor = require_central(request)
    if "ceir_auditor" not in actor.roles:
        raise HTTPException(status_code=403, detail="Independent audit permission required")
    result = verify_receipt(receipt, pinned_keys())
    return {
        **result, "key_id": receipt.key_id, "manifest_sha256": receipt.manifest_sha256,
        "signature_only": True, "local_checkpoint_compared": False,
        "externally_anchored": False, "simulated": True, "network_action_taken": False,
    }
