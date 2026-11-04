"""Independent offline Ed25519 receipts: valid, modified and untrusted cases."""
import base64
import hashlib
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from said.ceir.verifier import SignedReceipt, canonical_bytes, signing_bytes
from said.main import app
from said.security import Principal

client = TestClient(app)
PATH = "/api/v1/ceir/sandbox/verification/receipts/verify"

@contextmanager
def actor(roles=("said_admin", "ceir_auditor"), institution="said-central"):
    principal = Principal(subject="independent-auditor", institution=institution,
                          roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=principal), patch(
        "said.ceir.api.current_principal", return_value=principal
    ):
        yield

def receipt_fixture(monkeypatch):
    private = Ed25519PrivateKey.generate()
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    monkeypatch.setenv("SAID_AUDIT_PUBLIC_KEYS_JSON",
                       json.dumps({"test-key-1": base64.b64encode(pub).decode()}))
    manifest = {
        "schema": "said.mock.audit-checkpoint.v1",
        "checkpoint_id": "11111111-1111-4111-8111-111111111111",
        "investigation_id": "22222222-2222-4222-8222-222222222222",
        "sequence": 2, "head_digest": "a" * 64,
        "checkpoint_digest": "b" * 64,
        "reason_reference": "synthetic_audit_001"
    }
    body = {
        "version": "said.mock.receipt.v1", "key_id": "test-key-1",
        "manifest": manifest,
        "manifest_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "signature_b64": "",
    }
    unsigned = SignedReceipt.model_construct(**{**body, "manifest": body["manifest"]})
    # Build canonical signing payload without persisting any private key.
    signing_document = {k: body[k] for k in (
        "version", "key_id", "manifest", "manifest_sha256", "issued_at")}
    body["signature_b64"] = base64.b64encode(private.sign(
        canonical_bytes(signing_document))).decode()
    return body

def test_signed_receipt_and_tampering(monkeypatch):
    body = receipt_fixture(monkeypatch)
    with actor():
        good = client.post(PATH, json=body)
        assert good.status_code == 200, good.text
        assert good.json()["valid"] is True
        assert good.json()["signature_only"] is True
        assert good.json()["externally_anchored"] is False
        assert good.json()["network_action_taken"] is False
        altered = {**body, "manifest": {**body["manifest"], "sequence": 3}}
        invalid = client.post(PATH, json=altered)
        assert invalid.status_code == 200
        assert invalid.json()["valid"] is False
        assert invalid.json()["reason"] == "manifest_digest_mismatch"
        unknown = client.post(PATH, json={**body, "key_id": "untrusted-key"})
        assert unknown.json()["valid"] is False
        damaged = client.post(PATH, json={**body, "signature_b64": base64.b64encode(bytes(64)).decode()})
        assert damaged.json()["valid"] is False
        assert damaged.json()["reason"] == "invalid_signature"

def test_access_and_trust_store_fail_closed(monkeypatch):
    body = receipt_fixture(monkeypatch)
    assert client.post(PATH, json=body).status_code == 401
    with actor(("said_admin",), "said-central"):
        assert client.post(PATH, json=body).status_code == 403
    with actor(("said_admin", "ceir_auditor"), "mock_operator_alpha"):
        assert client.post(PATH, json=body).status_code == 403
    monkeypatch.delenv("SAID_AUDIT_PUBLIC_KEYS_JSON")
    with actor():
        assert client.post(PATH, json=body).status_code == 503
