"""Phase 21: backups must survive reopen and reject corrupt or unsafe recovery."""
import json
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_authority.authority import issue, open_store, get_receipt
from audit_authority.recovery import (
    backup_store, inspect_store, restore_backup, verify_backup,
)

MANIFEST = {
    "schema": "said.mock.audit-checkpoint.v1",
    "checkpoint_id": "99999999-9999-4999-8999-999999999999",
    "investigation_id": "88888888-8888-4888-8888-888888888888",
    "sequence": 1,
    "head_digest": "a" * 64,
    "checkpoint_digest": "b" * 64,
    "reason_reference": "recovery_case_01",
}

def test_backup_integrity_recovery_and_nonoverwrite(tmp_path):
    origin = str(tmp_path / "authority.db")
    backup = str(tmp_path / "authority-copy.db")
    recovered = str(tmp_path / "recovered.db")
    db = open_store(origin)
    try:
        original_receipt = issue(db, MANIFEST, "recovery-2026", Ed25519PrivateKey.generate())
        assert inspect_store(db)["receipts_checked"] == 1
        result = backup_store(origin, backup)
        assert result["keys_exported"] is False
        assert result["receipts_checked"] == 1
        digest = result["backup_sha256"]
        check = verify_backup(backup, digest)
        assert check["verified"] is True
        assert check["signatures_verified"] is False
        restored = restore_backup(backup, recovered, digest)
        assert restored["restore_complete"] is True
        with pytest.raises(FileExistsError):
            backup_store(origin, backup)
        with pytest.raises(FileExistsError):
            restore_backup(backup, recovered, digest)
        with pytest.raises(ValueError, match="digest mismatch"):
            verify_backup(backup, "0" * 64)
    finally:
        db.close()
    readback = open_store(recovered)
    try:
        assert get_receipt(readback, MANIFEST["checkpoint_id"]) == original_receipt
        assert inspect_store(readback)["receipts_checked"] == 1
    finally:
        readback.close()

def test_corrupt_backup_and_symlink_rejected(tmp_path):
    db = open_store(str(tmp_path / "authority.db"))
    db.close()
    path = str(tmp_path / "saved.db")
    result = backup_store(str(tmp_path / "authority.db"), path)
    (tmp_path / "saved.db").write_bytes(b"not-a-database")
    with pytest.raises(ValueError, match="digest mismatch"):
        restore_backup(path, str(tmp_path / "restore.db"), result["backup_sha256"])
    assert not (tmp_path / "restore.db").exists()
    link = tmp_path / "alias.db"
    link.symlink_to(tmp_path / "authority.db")
    with pytest.raises(ValueError, match="non-symlink"):
        verify_backup(str(link), result["backup_sha256"])

def test_receipt_corruption_fails_before_backup(tmp_path):
    path = str(tmp_path / "tampered.db")
    db = open_store(path)
    try:
        issue(db, MANIFEST, "audit-key-2026", Ed25519PrivateKey.generate())
        # Simulate a compromised DB owner replacing protective triggers.
        db.execute("DROP TRIGGER receipts_immutable_update")
        db.execute("UPDATE receipts SET receipt_digest = ?", ("0" * 64,))
        with pytest.raises(ValueError, match="digest mismatch"):
            inspect_store(db)
        with pytest.raises(ValueError):
            backup_store(path, str(tmp_path / "bad-backup.db"))
    finally:
        db.close()
