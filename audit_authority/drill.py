"""Isolated, nondestructive offline recovery drill for a mock receipt authority.

No signing keys, online connections, scheduled tasks or remote storage.
"""
import hashlib
import json
import os
import sqlite3
import stat
import tempfile
from pathlib import Path

from .recovery import backup_store, inspect_store, restore_backup, verify_backup


def _receipts(db_path: Path) -> dict[str, str]:
    """Read existing receipts without opening a writable operational store."""
    connection = sqlite3.connect(f"file:{db_path.resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        inspect_store(connection)
        return {
            row["checkpoint_id"]: hashlib.sha256(row["receipt_json"].encode("ascii")).hexdigest()
            for row in connection.execute("SELECT checkpoint_id, receipt_json FROM receipts")
        }
    finally:
        connection.close()


def recovery_drill(source_path: str, drill_parent: str) -> dict:
    """Backup, verify, restore, and reconcile an isolated disposable copy.

    Never creates a signing key or modifies the source authority database.
    Caller must choose an existing private directory on the audit host.
    """
    source = Path(source_path)
    parent = Path(drill_parent)
    if source.is_symlink() or not source.is_file():
        raise ValueError("Source must be a regular non-symlink database")
    if source.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Source database permissions must be 0600")
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("Recovery drill parent must be an existing directory")
    if parent.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("Recovery drill parent must be private (chmod 700)")
    baseline = _receipts(source)
    with tempfile.TemporaryDirectory(prefix="said-audit-drill-", dir=str(parent)) as temporary:
        work = Path(temporary)
        backup = work / "snapshot.db"
        restored = work / "restored.db"
        backed = backup_store(str(source), str(backup))
        checksum = backed["backup_sha256"]
        verified = verify_backup(str(backup), checksum)
        restored_report = restore_backup(str(backup), str(restored), checksum)
        copy = _receipts(restored)
        if copy != baseline:
            raise ValueError("Restored receipt set differs from operational snapshot")
        if not (
            backed["receipts_checked"] == verified["receipts_checked"]
            == restored_report["receipts_checked"] == len(copy)
        ):
            raise ValueError("Recovery drill receipt count mismatch")
        return {
            "drill_passed": True, "receipts_reconciled": len(copy),
            "snapshot_sha256": checksum, "isolated_copy": True,
            "existing_store_modified": False, "restored_copy_destroyed": True,
            "private_keys_exported": False, "signatures_verified": False,
            "external_immutable_backup": False, "simulated": True,
        }
