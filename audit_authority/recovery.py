"""Recovery operations for the separate, offline mock audit authority.

Backups preserve the *entire* SQLite database using SQLite's backup API.
Digests are corruption checks, not signatures or remote notarizations.
Neither the private signer key nor its passphrase is included in backups.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import stat
from pathlib import Path

from .authority import canonical, open_store, sha

def _private_regular(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular non-symlink audit file")
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Audit file permissions must be 0600")

def inspect_store(db: sqlite3.Connection) -> dict:
    """Validate database structure, receipts and append-only trigger presence."""
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity != "ok":
        raise ValueError("SQLite integrity check failed")
    names = {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger'")}
    for required in ("receipts_immutable_update", "receipts_immutable_delete"):
        if required not in names:
            raise ValueError("Append-only protection missing")
    checks = 0
    key_ids = set()
    for row in db.execute("SELECT checkpoint_id,manifest_digest,receipt_json,receipt_digest,key_id FROM receipts"):
        stored = row["receipt_json"]
        if sha(stored.encode("ascii")) != row["receipt_digest"]:
            raise ValueError("Receipt content digest mismatch")
        receipt = json.loads(stored)
        manifest = receipt.get("manifest")
        if not isinstance(manifest, dict):
            raise ValueError("Malformed stored receipt manifest")
        expected_manifest = sha(canonical(manifest))
        if (row["checkpoint_id"] != manifest.get("checkpoint_id") or
            receipt.get("manifest_sha256") != expected_manifest or
            row["manifest_digest"] != expected_manifest or
            row["key_id"] != receipt.get("key_id")):
            raise ValueError("Receipt metadata and manifest mismatch")
        checks += 1
        key_ids.add(row["key_id"])
    return {"integrity": "ok", "receipts_checked": checks,
            "key_ids": sorted(key_ids), "signature_validation": False,
            "external_anchor_verified": False, "simulated": True}

def backup_store(source: str, destination: str) -> dict:
    """Online-safe SQLite snapshot written exclusively into a new file."""
    src = Path(source).resolve(strict=True)
    _private_regular(src)
    dest = Path(destination).absolute()
    if src == dest:
        raise ValueError("Source and destination must differ")
    if dest.exists() or dest.is_symlink():
        raise FileExistsError("Backup destination already exists")
    if not dest.parent.is_dir():
        raise ValueError("Backup directory must already exist")
    source_db = open_store(str(src))
    temp = dest.parent / (".audit-backup-" + secrets.token_hex(12))
    try:
        inspect_store(source_db)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        backup_db = sqlite3.connect(str(temp))
        try:
            source_db.backup(backup_db)
            backup_db.commit()
        finally:
            backup_db.close()
        with sqlite3.connect(str(temp)) as db:
            db.row_factory = sqlite3.Row
            report = inspect_store(db)
        if dest.exists() or dest.is_symlink():
            raise FileExistsError("Backup destination already exists")
        # Hard links are not created by the backup process. Atomic rename
        # is local-only and the destination must be reserved by operators.
        os.link(temp, dest, follow_symlinks=False)
        os.unlink(temp)
        os.chmod(dest, 0o600)
        digest = hashlib.sha256(dest.read_bytes()).hexdigest()
        return {**report, "backup_sha256": digest, "path": str(dest),
                "backup_complete": True, "keys_exported": False}
    finally:
        source_db.close()
        if temp.exists():
            temp.unlink()

def verify_backup(source: str, expected_sha256: str) -> dict:
    path = Path(source)
    _private_regular(path)
    if len(expected_sha256) != 64 or any(x not in "0123456789abcdef" for x in expected_sha256):
        raise ValueError("Invalid expected SHA-256")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if not secrets.compare_digest(actual, expected_sha256):
        raise ValueError("Backup digest mismatch")
    # Read-only ensures verification does not create or mutate the backup.
    db = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    try:
        report = inspect_store(db)
    finally:
        db.close()
    return {**report, "backup_sha256": actual, "verified": True,
            "signatures_verified": False, "keys_exported": False}

def restore_backup(source: str, destination: str, expected_sha256: str) -> dict:
    """Refuse to replace existing databases, directories or symlink targets."""
    report = verify_backup(source, expected_sha256)
    dest = Path(destination).absolute()
    if dest.exists() or dest.is_symlink():
        raise FileExistsError("Restore target already exists")
    if not dest.parent.is_dir():
        raise ValueError("Restore directory must already exist")
    temp = dest.parent / (".audit-restore-" + secrets.token_hex(12))
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output, open(source, "rb") as inp:
            while True:
                chunk = inp.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if hashlib.sha256(temp.read_bytes()).hexdigest() != expected_sha256:
            raise ValueError("Restore copy digest mismatch")
        os.link(temp, dest, follow_symlinks=False)
        os.unlink(temp)
        os.chmod(dest, 0o600)
        return {**report, "restored_to": str(dest), "restore_complete": True}
    finally:
        if temp.exists():
            temp.unlink()
