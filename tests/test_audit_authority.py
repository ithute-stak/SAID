"""Independent simulated authority: persistence, signature, tampering and key custody."""
import base64
import hashlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from audit_authority.authority import (
    canonical, get_receipt, issue, load_encrypted_signer, open_store, reconcile,
)
from said.ceir.verifier import SignedReceipt, verify_receipt

MANIFEST = {
    "schema": "said.mock.audit-checkpoint.v1",
    "checkpoint_id": "11111111-1111-4111-8111-111111111111",
    "investigation_id": "22222222-2222-4222-8222-222222222222",
    "sequence": 2, "head_digest": "a" * 64,
    "checkpoint_digest": "b" * 64, "reason_reference": "offline_fixture_2026",
}

def private_fixture(tmp_path):
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"synthetic-test-only-passphrase-2026"),
    )
    path = tmp_path / "signer.pem"
    path.write_bytes(pem)
    path.chmod(0o600)
    return path, private

def test_separate_authority_receipts_reconciliation_and_verification(tmp_path):
    path, private = private_fixture(tmp_path)
    signer = load_encrypted_signer(str(path), "synthetic-test-only-passphrase-2026")
    dbpath = str(tmp_path / "external-receipts.db")
    db = open_store(dbpath)
    try:
        receipt = issue(db, MANIFEST, "audit-local-2026", signer)
        trusted = {"audit-local-2026": private.public_key()}
        assert verify_receipt(SignedReceipt.model_validate(receipt), trusted)["valid"] is True
        assert get_receipt(db, MANIFEST["checkpoint_id"]) == receipt
        assert issue(db, MANIFEST, "audit-local-2026", signer) == receipt
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
        with pytest.raises(ValueError, match="different manifest"):
            issue(db, {**MANIFEST, "sequence": 3}, "audit-local-2026", signer)
        report = reconcile(db, [MANIFEST, {**MANIFEST,
            "checkpoint_id": "33333333-3333-4333-8333-333333333333"}])
        assert [x["status"] for x in report["results"]] == [
            "digest_match_only", "missing_receipt"
        ]
        assert report["external_transfer"] is False
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute("UPDATE receipts SET key_id='modified'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute("DELETE FROM receipts")
    finally:
        db.close()
    # A newly opened independent store still serves the same receipt.
    db = open_store(dbpath)
    try:
        assert get_receipt(db, MANIFEST["checkpoint_id"]) == receipt
    finally:
        db.close()

def test_encrypted_key_permissions_are_required(tmp_path):
    path, private = private_fixture(tmp_path)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="chmod"):
        load_encrypted_signer(str(path), "synthetic-test-only-passphrase-2026")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        load_encrypted_signer(str(path), "incorrect-passphrase-xyz")
    with pytest.raises(ValueError, match="passphrase"):
        load_encrypted_signer(str(path), "")
    plain = tmp_path / "unencrypted.pem"
    plain.write_bytes(private.private_bytes(
        Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    plain.chmod(0o600)
    with pytest.raises(ValueError, match="encrypted"):
        load_encrypted_signer(str(plain), "synthetic-test-only-passphrase-2026")

def test_receipt_matches_existing_said_contract(tmp_path):
    _, private = private_fixture(tmp_path)
    db = open_store(str(tmp_path / "receipt-store.db"))
    try:
        receipt = issue(db, MANIFEST, "test-pub-key", private,
                        issued_at=datetime.now(timezone.utc).isoformat())
        payload = SignedReceipt.model_validate(receipt)
        assert verify_receipt(payload, {"test-pub-key": private.public_key()})["valid"]
        bad = SignedReceipt.model_validate({
            **receipt, "manifest": {**receipt["manifest"], "head_digest": "0" * 64}})
        assert verify_receipt(bad, {"test-pub-key": private.public_key()})["valid"] is False
    finally:
        db.close()
