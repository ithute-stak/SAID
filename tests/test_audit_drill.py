"""Phase 22: recovery drills and key registry are non-destructive and fail closed."""
import base64
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from audit_authority.authority import issue, open_store
from audit_authority.drill import recovery_drill
from audit_authority.key_policy import validate_registry

MANIFEST = {
    "schema": "said.mock.audit-checkpoint.v1",
    "checkpoint_id": "a1111111-1111-4111-8111-111111111111",
    "investigation_id": "b2222222-2222-4222-8222-222222222222",
    "sequence": 1, "head_digest": "a" * 64,
    "checkpoint_digest": "b" * 64, "reason_reference": "phase22_drill",
}

def fixture_db(tmp_path):
    dbpath = tmp_path / "receipts.db"
    db = open_store(str(dbpath))
    try:
        issue(db, MANIFEST, "drill-key-1", Ed25519PrivateKey.generate())
    finally:
        db.close()
    parent = tmp_path / "drills"
    parent.mkdir(mode=0o700)
    return dbpath, parent

def test_recovery_drill_restores_complete_receipt_set_without_mutation(tmp_path):
    source, parent = fixture_db(tmp_path)
    original_bytes = source.read_bytes()
    result = recovery_drill(str(source), str(parent))
    assert result["drill_passed"] is True
    assert result["receipts_reconciled"] == 1
    assert result["existing_store_modified"] is False
    assert result["private_keys_exported"] is False
    assert result["external_immutable_backup"] is False
    assert source.read_bytes() == original_bytes
    assert list(parent.iterdir()) == []
    assert recovery_drill(str(source), str(parent))["drill_passed"] is True

def test_recovery_drill_private_directory_and_symlink(tmp_path):
    source, parent = fixture_db(tmp_path)
    parent.chmod(0o755)
    with pytest.raises(ValueError, match="private"):
        recovery_drill(str(source), str(parent))
    parent.chmod(0o700)
    alias = tmp_path / "link.db"
    alias.symlink_to(source)
    with pytest.raises(ValueError, match="non-symlink"):
        recovery_drill(str(alias), str(parent))

def test_public_key_lifecycle_validation(tmp_path):
    key = Ed25519PrivateKey.generate()
    key2 = Ed25519PrivateKey.generate()
    def item(name, private, state, activated=None, retired=None):
        pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return {
            "key_id": name, "public_key_b64": base64.b64encode(pub).decode(),
            "state": state, "approved_by": "two_person_committee",
            "approved_reference": "signed_approval_001",
            "activated_at": activated, "retired_at": retired,
        }
    data = {"version": "said.mock.audit-public-keys.v1", "keys": [
        item("audit-2026-a", key, "active", "2026-11-04T00:00:00+00:00"),
        item("audit-2026-b", key2, "staged"),
    ]}
    report = validate_registry(data)
    assert report["active_key_id"] == "audit-2026-a"
    assert report["private_keys_loaded"] is False
    assert report["rotation_performed"] is False
    with pytest.raises(ValueError, match="Duplicate key ID"):
        validate_registry({**data, "keys": [data["keys"][0], data["keys"][0]]})
    with pytest.raises(ValueError, match="Public key reused"):
        validate_registry({**data, "keys": [data["keys"][0], {**data["keys"][0], "key_id": "another-id"}]})
    with pytest.raises(ValueError, match="Exactly one active"):
        validate_registry({**data, "keys": [{**data["keys"][0], "state": "staged", "activated_at": None}, data["keys"][1]]})
