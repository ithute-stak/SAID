"""Governance lifecycle keeps original case decisions separate from appeals."""
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
    p = Principal(subject=subject, institution=institution, roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=p), patch(
        "said.ceir.api.current_principal", return_value=p
    ):
        yield

def test_four_party_appeal_and_audit(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY", "phase16-synthetic-only-key-123456789876543")
    with actor("investigator"):
        obs = client.post(BASE + "/quality/observations", json={
            "source_code": "mock_operator_alpha",
            "reference": "appeal_" + uuid.uuid4().hex,
            "imei": "490154203237518"})
        assert obs.status_code == 201, obs.text
        o = obs.json()["id"]
        case = client.post(BASE + "/quality/observations/" + o + "/investigation")
        assert case.status_code == 201, case.text
        case_id = case.json()["id"]
        assert client.post(BASE + "/appeals", json={
            "investigation_id": case_id, "reason_reference": "too_early"}).status_code == 403
    with actor("reviewer", ("said_admin", "ceir_reviewer")):
        reviewed = client.post(BASE + "/quality/investigations/" + case_id + "/review",
            json={"decision": "insufficient_evidence", "decision_reference": "review_001"})
        assert reviewed.status_code == 200, reviewed.text
    appeal_data = {"investigation_id": case_id, "reason_reference": "request_002"}
    with actor("investigator", ("said_admin", "ceir_appeals_officer")):
        assert client.post(BASE + "/appeals", json=appeal_data).status_code == 403
    with actor("reviewer", ("said_admin", "ceir_appeals_officer")):
        assert client.post(BASE + "/appeals", json=appeal_data).status_code == 403
    with actor("appeals-officer", ("said_admin", "ceir_appeals_officer")):
        opened = client.post(BASE + "/appeals", json=appeal_data)
        assert opened.status_code == 201, opened.text
        appeal_id = opened.json()["id"]
        assert client.post(BASE + "/appeals", json=appeal_data).status_code == 409
        queue = client.get(BASE + "/appeals")
        assert appeal_id in [row["id"] for row in queue.json()]
    endpoint = BASE + "/appeals/" + appeal_id + "/decide"
    decision = {"outcome": "returned_for_further_review",
                "decision_reference": "supervisor_003"}
    with actor("appeals-officer", ("said_admin", "ceir_supervisor")):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("reviewer", ("said_admin", "ceir_supervisor")):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("independent-supervisor", ("said_admin", "ceir_supervisor")):
        result = client.post(endpoint, json=decision)
        assert result.status_code == 200, result.text
        assert result.json()["state"] == "returned_for_further_review"
        assert result.json()["network_action_taken"] is False
        assert client.post(endpoint, json=decision).status_code == 409
        integrity = client.get(BASE + "/governance/investigations/" + case_id + "/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["valid"] is True
        assert integrity.json()["events_checked"] == 4
        history = client.get(BASE + "/appeals/" + appeal_id)
        assert history.json()["reviewed_by"] == "independent-supervisor"

def test_restricted_staff_access():
    assert client.get(BASE + "/appeals").status_code == 401
    with actor("institutional-admin", ("said_admin",), "operator-foreign"):
        assert client.get(BASE + "/appeals").status_code == 403
    with actor("central-admin"):
        assert client.get(BASE + "/appeals").status_code == 403
