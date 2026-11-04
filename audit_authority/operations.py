"""Read-only audit-health and backup inventory, plus local recovery drill reports.

No networking, scheduling, external alerts, key access or production evidence
transmission. Digest comparisons do not replace an independent signed catalog.
"""
import hashlib
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .drill import recovery_drill
from .recovery import _private_regular, inspect_store, verify_backup

class InventoryEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.-]+$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(pattern=r"^said[.]mock[.]backup-inventory[.]v1$")
    entries: list[InventoryEntry] = Field(min_length=1, max_length=100)


def health_report(source_path: str) -> dict:
    """Observe the live audit store strictly read-only; never create it."""
    path = Path(source_path)
    try:
        _private_regular(path)
        db = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            result = inspect_store(db)
        finally:
            db.close()
        return {"healthy": True, "severity": "ok", "details": result,
                "network_alert_sent": False, "simulated": True}
    except (OSError, ValueError, sqlite3.Error, json.JSONDecodeError, UnicodeError) as exc:
        # Error type, not filesystem paths or source receipt data.
        return {"healthy": False, "severity": "critical",
                "error_type": type(exc).__name__,
                "network_alert_sent": False, "simulated": True}


def check_inventory(folder: str, inventory_data: dict) -> dict:
    """Check a supplied independent checksum catalog against private local files.

    The catalog must come from a separately authenticated, operator-approved
    source; this function does not establish that authenticity.
    """
    directory = Path(folder)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("Inventory directory must be a real directory")
    if directory.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Inventory directory must be mode 0700")
    catalog = Inventory.model_validate(inventory_data)
    filenames = [e.filename for e in catalog.entries]
    if len(set(filenames)) != len(filenames) or any(name in {".", ".."} for name in filenames):
        raise ValueError("Duplicate or unsafe inventory filenames")
    findings = []
    for entry in catalog.entries:
        path = directory / entry.filename
        if not path.exists() or path.is_symlink():
            findings.append({"filename": entry.filename, "status": "missing"})
            continue
        try:
            report = verify_backup(str(path), entry.sha256)
            findings.append({"filename": entry.filename, "status": "verified",
                             "receipts_checked": report["receipts_checked"]})
        except (ValueError, sqlite3.Error, OSError, UnicodeError):
            findings.append({"filename": entry.filename, "status": "invalid_or_mismatch"})
    success = all(item["status"] == "verified" for item in findings)
    return {"healthy": success, "severity": "ok" if success else "critical",
            "results": findings, "catalog_authenticated": False,
            "offsite_copies_verified": False, "simulated": True}


def record_drill(source: str, parent: str, report_path: str) -> dict:
    """Perform a local drill and append one sanitized JSONL operator record.

    The report may not be colocated with the authority database, cannot be
    a symlink, and must be an existing private file or a new private path.
    """
    output = Path(report_path)
    if output.is_symlink() or output.resolve() == Path(source).resolve():
        raise ValueError("Refusing unsafe report location")
    if not output.parent.is_dir() or output.parent.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Report parent directory must be private")
    if output.exists():
        _private_regular(output)
    occurred_at = datetime.now(timezone.utc).isoformat()
    try:
        result = recovery_drill(source, parent)
        event = {"event": "offline_recovery_drill", "timestamp": occurred_at,
                 "outcome": "success", "receipts_reconciled": result["receipts_reconciled"],
                 "snapshot_sha256": result["snapshot_sha256"]}
    except Exception as exc:
        event = {"event": "offline_recovery_drill", "timestamp": occurred_at,
                 "outcome": "failure", "error_type": type(exc).__name__}
    event.update({"simulated": True, "external_alert_sent": False,
                  "report_signed": False})
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(output, flags, 0o600)
    try:
        if os.fstat(fd).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError("Unsafe report permissions")
        os.write(fd, (json.dumps(event, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return event
