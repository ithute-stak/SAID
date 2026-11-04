"""Offline quality signals are non-accusatory and never cause network actions."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

@contextmanager
def actor(institution, roles):
    principal = Principal(subject="quality-" + uuid.uuid4().hex,
                          institution=institution, roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=principal), patch(
        "said.ceir.api.current_principal", return_value=principal
    ):
        yield

def sample(source, ref, imei="490154203237518"):
    return client.post("/api/v1/ceir/sandbox/quality/observations", json={
        "source_code": source, "reference": ref, "imei": imei})

def test_repeat_signal_review_and_safety(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY", "test-hmac-secret-not-for-production-987654321")
    with actor("said-central", {"said_admin"}):
        a = sample("mock_operator_alpha", "A_" + uuid.uuid4().hex)
        assert a.status_code == 201, a.text
        aid = a.json()["id"]
        assert "imei" not in a.json()
        ref = "B_" + uuid.uuid4().hex
        b = sample("mock_operator_beta", ref)
        assert b.status_code == 201, b.text
        assert sample("mock_operator_beta", ref).json()["id"] == b.json()["id"]
        report = client.get("/api/v1/ceir/sandbox/quality/observations/" + aid)
        assert report.status_code == 200, report.text
        body = report.json()
        assert body["distinct_mock_sources"] == 2
        assert body["observations_with_same_imei"] >= 2
        assert "observed_across_multiple_mock_sources" in body["indicators"]
        assert body["changed_imei_detected"] is False
        assert body["theft_determined"] is False
        assert body["network_action_taken"] is False
        created = client.post("/api/v1/ceir/sandbox/quality/observations/" + aid + "/investigation")
        assert created.status_code == 201, created.text
        iid = created.json()["id"]
        reviewed = client.post("/api/v1/ceir/sandbox/quality/investigations/" + iid + "/review", json={
            "decision": "insufficient_evidence", "decision_reference": "review_case_1"})
        assert reviewed.status_code == 403
        assert reviewed.json()["detail"] == "Independent CEIR reviewer role required"
        assert client.post("/api/v1/ceir/sandbox/quality/investigations/" + iid + "/review", json={
            "decision": "closed_false_positive", "decision_reference": "review_case_2"}).status_code == 403
        assert sample("mock_operator_alpha", "bad_" + uuid.uuid4().hex, "490154203237519").status_code == 422

def test_access_and_secret_fail_closed(monkeypatch):
    monkeypatch.delenv("SAID_CEIR_HMAC_KEY", raising=False)
    with actor("said-central", {"said_admin"}):
        assert sample("mock_operator_alpha", "missing_key").status_code == 503
    with actor("untrusted-institution", {"said_admin"}):
        assert sample("mock_operator_alpha", "not_allowed").status_code == 403
    assert sample("mock_operator_alpha", "anonymous").status_code == 401
