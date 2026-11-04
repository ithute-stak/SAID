"""Independent reviewer and governance integration tests."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)
BASE = "/api/v1/ceir/sandbox"

@contextmanager
def actor(subject, roles=("said_admin",), institution="said-central"):
    p = Principal(subject=subject, roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal", return_value=p), patch(
        "said.ceir.api.current_principal", return_value=p
    ):
        yield

def test_independent_review_with_event_history(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY", "dev-test-governance-key-123456789012345")
    with actor("opener"):
        r = client.post(BASE + "/quality/observations", json={
            "source_code": "mock_operator_alpha",
            "reference": "phase15_" + uuid.uuid4().hex,
            "imei": "490154203237518"})
        assert r.status_code == 201, r.text
        r = client.post(BASE + "/quality/observations/" + r.json()["id"] + "/investigation")
        assert r.status_code == 201, r.text
        case_id = r.json()["id"]
    endpoint = BASE + "/quality/investigations/" + case_id + "/review"
    decision = {"decision": "insufficient_evidence", "decision_reference": "example_review_1"}
    with actor("opener", ("said_admin", "ceir_reviewer")):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("reviewer", ("said_admin",)):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("reviewer", ("said_admin", "ceir_reviewer")):
        r = client.post(endpoint, json=decision)
        assert r.status_code == 200, r.text
        assert r.json()["network_action_taken"] is False
        assert client.post(endpoint, json=decision).status_code == 409
        r = client.get(BASE + "/governance/investigations/" + case_id + "/integrity")
        assert r.status_code == 200, r.text
        assert r.json()["valid"] is True
        assert r.json()["events_checked"] == 2
        r = client.get(BASE + "/governance/retention/preview")
        assert r.status_code == 200
        assert r.json()["records_deleted"] == 0
        assert r.json()["preview_only"] is True

def test_governance_authorization_and_policy(monkeypatch):
    monkeypatch.setenv("SAID_MOCK_RETENTION_DAYS", "0")
    with actor("admin"):
        assert client.get(BASE + "/governance/retention/preview").status_code == 503
    with actor("foreign", institution="operator-a"):
        assert client.get(BASE + "/governance/retention/preview").status_code == 403
    assert client.get(BASE + "/governance/retention/preview").status_code == 401
