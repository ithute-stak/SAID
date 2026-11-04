"""Evidence provenance and explainable assessment snapshots (mock inputs only)."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

@contextmanager
def actor(institution="said-central", roles=("said_admin",)):
    principal = Principal(subject="reviewer-" + uuid.uuid4().hex,
                          roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal", return_value=principal), patch(
        "said.ceir.api.current_principal", return_value=principal
    ):
        yield

def observation(source):
    ref = "PROVENANCE_" + uuid.uuid4().hex
    response = client.post("/api/v1/ceir/sandbox/quality/observations", json={
        "source_code": source, "reference": ref, "imei": "490154203237518"
    })
    assert response.status_code == 201, response.text
    return response.json()["id"]

def test_provenance_and_snapshot_history(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY", "dev-only-intelligence-test-secret-123456789")
    with actor():
        first = observation("mock_operator_alpha")
        evidence = {"observation_id": first, "source_code": "mock_operator_alpha",
                    "provenance_kind": "synthetic_fixture",
                    "evidence_reference": "fixture_case_01"}
        wrong = client.post("/api/v1/ceir/sandbox/intelligence/provenance",
                            json={**evidence, "source_code": "mock_operator_beta"})
        assert wrong.status_code == 409
        added = client.post("/api/v1/ceir/sandbox/intelligence/provenance", json=evidence)
        assert added.status_code == 201, added.text
        assert client.post("/api/v1/ceir/sandbox/intelligence/provenance",
                           json=evidence).status_code == 409
        fetched = client.get("/api/v1/ceir/sandbox/intelligence/observations/" +
                             first + "/provenance")
        assert fetched.status_code == 200
        assert fetched.json()["evidence_reference"] == "fixture_case_01"

        other = observation("mock_operator_beta")
        path = "/api/v1/ceir/sandbox/intelligence/observations/" + first + "/assessments"
        assessment = client.post(path)
        assert assessment.status_code == 201, assessment.text
        state = assessment.json()
        assert state["distinct_mock_sources"] == 2
        assert state["observations_with_same_imei"] >= 2
        assert state["confidence"] == "corroboration_required"
        assert state["imei_changed"] is False
        assert state["theft_determined"] is False
        assert state["network_action_taken"] is False
        assert "incomplete_mock_provenance" in state["indicators"]
        assert "imei_token" not in assessment.text
        assert "490154203237518" not in assessment.text
        second = client.post(path)
        assert second.status_code == 201
        history = client.get(path)
        assert history.status_code == 200
        assert [x["id"] for x in history.json()][-2:] == [
            assessment.json()["id"], second.json()["id"]
        ]
        case = client.post("/api/v1/ceir/sandbox/quality/observations/" +
                           other + "/investigation")
        assert case.status_code == 201
        queue = client.get("/api/v1/ceir/sandbox/intelligence/investigations")
        assert queue.status_code == 200
        assert case.json()["id"] in [i["id"] for i in queue.json()]

def test_central_authorization():
    with actor("another-institution", ("said_admin",)):
        assert client.get("/api/v1/ceir/sandbox/intelligence/investigations").status_code == 403
    assert client.get("/api/v1/ceir/sandbox/intelligence/investigations").status_code == 401
