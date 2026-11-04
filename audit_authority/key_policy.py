"""Read-only public-key lifecycle assessment for audit-authority preparations.

The authority cannot rotate keys, export private keys, or provision SAID
trust configuration. All dates and fingerprints must be independently approved.
"""
import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class PublicKeyEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    public_key_b64: str = Field(min_length=43, max_length=48)
    state: Literal["staged", "active", "retired", "revoked"]
    approved_by: str = Field(min_length=3, max_length=120)
    approved_reference: str = Field(min_length=3, max_length=120)
    activated_at: str | None = None
    retired_at: str | None = None


def validate_registry(data: dict) -> dict:
    if not isinstance(data, dict) or set(data) != {"version", "keys"}:
        raise ValueError("Expected version and keys only")
    if data["version"] != "said.mock.audit-public-keys.v1":
        raise ValueError("Unsupported registry version")
    entries = data["keys"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 20:
        raise ValueError("Expected 1 to 20 public-key entries")
    ids = set()
    fingerprints = set()
    active = []
    output = []
    for raw in entries:
        item = PublicKeyEntry.model_validate(raw)
        if item.key_id in ids:
            raise ValueError("Duplicate key ID")
        ids.add(item.key_id)
        try:
            decoded = base64.b64decode(item.public_key_b64, validate=True)
            if len(decoded) != 32:
                raise ValueError("Wrong Ed25519 public key length")
            Ed25519PublicKey.from_public_bytes(decoded)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Invalid Ed25519 public key") from exc
        fingerprint = hashlib.sha256(decoded).hexdigest()
        if fingerprint in fingerprints:
            raise ValueError("Public key reused under another key ID")
        fingerprints.add(fingerprint)
        if item.state == "active":
            if not item.activated_at or item.retired_at:
                raise ValueError("Active key requires activation and no retirement")
            active.append(item.key_id)
        if item.state in ("retired", "revoked") and not item.retired_at:
            raise ValueError("Retired or revoked key needs retirement timestamp")
        for value in (item.activated_at, item.retired_at):
            if value is not None:
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if parsed.tzinfo is None:
                        raise ValueError("Date must be timezone aware")
                except (TypeError, ValueError) as exc:
                    raise ValueError("Invalid key lifecycle date") from exc
        output.append({"key_id": item.key_id, "state": item.state,
                       "fingerprint_sha256": fingerprint})
    if len(active) != 1:
        raise ValueError("Exactly one active signing key required in this prototype")
    return {"valid": True, "active_key_id": active[0],
            "entries": output, "private_keys_loaded": False,
            "rotation_performed": False, "simulated": True}
