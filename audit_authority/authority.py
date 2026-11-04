"""Offline, independently operated mock-audit authority.

Run as a different OS user with a separate SQLite DB and encrypted private
key; NEVER load this module into the SAID FastAPI process. No networking.
"""
import base64
import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema: Literal["said.mock.audit-checkpoint.v1"]
    checkpoint_id: str = Field(min_length=36, max_length=36)
    investigation_id: str = Field(min_length=36, max_length=36)
    sequence: int = Field(ge=1)
    head_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_-]+$")

def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def load_encrypted_signer(file: str, passphrase: str) -> Ed25519PrivateKey:
    """Fail closed on world/group-readable keys and unencrypted PEM."""
    path = Path(file)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Signer must be a regular non-symlink key file")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Signer key must be private to service account (chmod 600)")
    if not passphrase or len(passphrase) < 16:
        raise ValueError("Encrypted signing key passphrase required")
    data = path.read_bytes()
    if b"ENCRYPTED PRIVATE KEY" not in data:
        raise ValueError("Only encrypted PKCS8 private keys accepted")
    key = serialization.load_pem_private_key(data, password=passphrase.encode())
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 signing key")
    return key

def open_store(path: str) -> sqlite3.Connection:
    dbpath = Path(path)
    if dbpath.is_symlink():
        raise ValueError("Store must not be a symlink")
    dbpath.parent.mkdir(parents=True, exist_ok=True)
    if dbpath.exists() and dbpath.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Store file must be private to service account")
    connection = sqlite3.connect(str(dbpath), timeout=5, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = DELETE")
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS receipts (
            checkpoint_id TEXT PRIMARY KEY,
            manifest_digest TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            receipt_digest TEXT NOT NULL,
            key_id TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS receipts_immutable_update
            BEFORE UPDATE ON receipts BEGIN SELECT RAISE(ABORT,'append-only receipts'); END;
        CREATE TRIGGER IF NOT EXISTS receipts_immutable_delete
            BEFORE DELETE ON receipts BEGIN SELECT RAISE(ABORT,'append-only receipts'); END;
    """)
    os.chmod(dbpath, 0o600)
    return connection

def issue(db: sqlite3.Connection, manifest_input: dict, key_id: str,
          private: Ed25519PrivateKey, issued_at: str | None = None) -> dict:
    """Create an idempotent receipt, failing closed on a changed checkpoint."""
    if not (3 <= len(key_id) <= 64) or not all(c.isalnum() or c in "_.-" for c in key_id):
        raise ValueError("Invalid key ID")
    manifest = Manifest.model_validate(manifest_input).model_dump()
    manifest_digest = sha(canonical(manifest))
    checkpoint = manifest["checkpoint_id"]
    db.execute("BEGIN IMMEDIATE")
    try:
        existing = db.execute(
            "SELECT manifest_digest, receipt_json FROM receipts WHERE checkpoint_id=?",
            (checkpoint,)).fetchone()
        if existing is not None:
            if existing["manifest_digest"] != manifest_digest:
                raise ValueError("Checkpoint already recorded with different manifest")
            receipt = json.loads(existing["receipt_json"])
            # Preserve original immutable receipt and key ID on replay.
            db.execute("COMMIT")
            return receipt
        receipt = {
            "version": "said.mock.receipt.v1", "key_id": key_id,
            "manifest": manifest, "manifest_sha256": manifest_digest,
            "issued_at": issued_at or datetime.now(timezone.utc).isoformat(),
        }
        signature = private.sign(canonical(receipt))
        receipt["signature_b64"] = base64.b64encode(signature).decode("ascii")
        db.execute(
            "INSERT INTO receipts(checkpoint_id,manifest_digest,receipt_json,receipt_digest,key_id) VALUES (?,?,?,?,?)",
            (checkpoint, manifest_digest, canonical(receipt).decode("ascii"),
             sha(canonical(receipt)), key_id),
        )
        db.execute("COMMIT")
        return receipt
    except Exception:
        db.execute("ROLLBACK")
        raise

def get_receipt(db: sqlite3.Connection, checkpoint_id: str) -> dict | None:
    row = db.execute("SELECT receipt_json,receipt_digest FROM receipts WHERE checkpoint_id=?",
                     (checkpoint_id,)).fetchone()
    if row is None:
        return None
    if sha(row["receipt_json"].encode("ascii")) != row["receipt_digest"]:
        raise ValueError("Stored receipt failed integrity check")
    return json.loads(row["receipt_json"])

def reconcile(db: sqlite3.Connection, manifests: list[dict]) -> dict:
    """Offline reconciliation; never fetch SAID data over the network."""
    findings = []
    for item in manifests:
        manifest = Manifest.model_validate(item).model_dump()
        existing = get_receipt(db, manifest["checkpoint_id"])
        if existing is None:
            findings.append({"checkpoint_id": manifest["checkpoint_id"], "status": "missing_receipt"})
        elif existing["manifest_sha256"] != sha(canonical(manifest)):
            findings.append({"checkpoint_id": manifest["checkpoint_id"], "status": "manifest_mismatch"})
        else:
            findings.append({"checkpoint_id": manifest["checkpoint_id"], "status": "digest_match_only"})
    return {"results": findings, "simulated": True,
            "signatures_verified": False, "external_transfer": False}
