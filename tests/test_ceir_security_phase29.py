"""Phase 29 API abuse, actor boundary, input validation, and replay tests.

All fixtures use synthetic mock CEIR records; no carrier access.
"""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from said.main import app
from said.security import Principal

client = TestClient(app)
ROOT = "/api/v1/ceir/sandbox"

@contextmanager
def actor(subject, roles=("said_admin",), institution="said-central"):
    principal = Principal(subject=subject, institution=institution,
                          roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=principal), patch(
         "said.ceir.api.current_principal", return_value=principal):
        yield

def reviewed_case(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY",
                       "synthetic-phase29-hmac-private-testing-1234")
    with actor("case-opener"):
        observation = client.post(ROOT + "/quality/observations", json={
            "source_code": "mock_operator_alpha",
            "reference": "PH29_" + uuid.uuid4().hex,
            "imei": "490154203237518"
        })
        assert observation.status_code == 201, observation.text
        started = client.post(ROOT + "/quality/observations/" +
                              observation.json()["id"] + "/investigation")
        assert started.status_code == 201, started.text
        case = started.json()["id"]
    with actor("reviewer-29", ("said_admin", "ceir_reviewer")):
        result = client.post(ROOT + "/quality/investigations/" +
                             case + "/review", json={
            "decision": "insufficient_evidence",
            "decision_reference": "phase29_review"})
        assert result.status_code == 200, result.text
    return case

@pytest.mark.parametrize("route,payload", [
    ("/quality/observations", {"source_code": "mock_operator_alpha",
                              "reference": "SEC_123", "imei": "490154203237518"}),
    ("/appeals", {"investigation_id": "11111111-1111-4111-8111-111111111111",
                  "reason_reference": "appeal_123"}),
    ("/oversight/holds", {"investigation_id": "11111111-1111-4111-8111-111111111111",
                          "reason_reference": "hold_123"}),
    ("/assurance/retention-plans",
     {"investigation_id": "11111111-1111-4111-8111-111111111111",
      "rationale_reference": "retain_123"}),
])
def test_anonymous_and_external_tenant_cannot_write(route, payload):
    assert client.post(ROOT + route, json=payload).status_code == 401
    with actor("foreign-staff", ("said_admin", "ceir_supervisor",
                                "ceir_appeals_officer"), "foreign-institution"):
        assert client.post(ROOT + route, json=payload).status_code == 403

@pytest.mark.parametrize("payload", [
    {"source_code": "mock_operator_alpha", "reference": "x", "imei": "490154203237518"},
    {"source_code": "carrier_live", "reference": "SEC_456", "imei": "490154203237518"},
    {"source_code": "mock_operator_alpha", "reference": "SEC_789", "imei": "49015420323751X"},
    {"source_code": "mock_operator_alpha", "reference": "../../etc/passwd", "imei": "490154203237518"},
])
def test_malformed_observation_rejected(payload, monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY",
                       "synthetic-phase29-hmac-private-testing-1234")
    with actor("case-opener"):
        assert client.post(ROOT + "/quality/observations", json=payload).status_code == 422

def test_replay_and_independent_role_checks(monkeypatch):
    case = reviewed_case(monkeypatch)
    review_url = ROOT + "/quality/investigations/" + case + "/review"
    with actor("reviewer-29", ("said_admin", "ceir_reviewer")):
        replay = client.post(review_url, json={
            "decision": "needs_investigation",
            "decision_reference": "phase29_replay"})
        assert replay.status_code == 409
    with actor("case-opener", ("said_admin", "ceir_appeals_officer")):
        denied = client.post(ROOT + "/appeals", json={
            "investigation_id": case, "reason_reference": "self_appeal"})
        assert denied.status_code == 403
    with actor("reviewer-29", ("said_admin", "ceir_appeals_officer")):
        denied = client.post(ROOT + "/appeals", json={
            "investigation_id": case, "reason_reference": "reviewer_appeal"})
        assert denied.status_code == 403
    with actor("appeals-29", ("said_admin", "ceir_appeals_officer")):
        appeal = client.post(ROOT + "/appeals", json={
            "investigation_id": case, "reason_reference": "valid_appeal"})
        assert appeal.status_code == 201, appeal.text
        repeated = client.post(ROOT + "/appeals", json={
            "investigation_id": case, "reason_reference": "repeat_appeal"})
        assert repeated.status_code == 409
        appeal_id = appeal.json()["id"]
    with actor("appeals-29", ("said_admin", "ceir_supervisor")):
        denied = client.post(ROOT + "/appeals/" + appeal_id + "/decide",
                             json={"outcome": "original_review_upheld",
                                   "decision_reference": "self_review"})
        assert denied.status_code == 403
    with actor("supervisor-29", ("said_admin", "ceir_supervisor")):
        decided = client.post(ROOT + "/appeals/" + appeal_id + "/decide",
                              json={"outcome": "original_review_upheld",
                                    "decision_reference": "different_supervisor"})
        assert decided.status_code == 200, decided.text
        assert client.post(ROOT + "/appeals/" + appeal_id + "/decide",
                           json={"outcome": "original_review_upheld",
                                 "decision_reference": "replay_supervisor"}).status_code == 409
        integrity = client.get(ROOT + "/governance/investigations/" +
                               case + "/integrity")
        assert integrity.status_code == 200
        assert integrity.json()["valid"] is True

def test_injection_like_references_rejected_before_state_changes(monkeypatch):
    case = reviewed_case(monkeypatch)
    with actor("other-officer", ("said_admin", "ceir_appeals_officer")):
        for reason in ("../escape", "drop table appeals;", "a" * 121, "x y"):
            result = client.post(ROOT + "/appeals", json={
                "investigation_id": case, "reason_reference": reason})
            assert result.status_code == 422
        result = client.post(ROOT + "/appeals", json={
            "investigation_id": case, "reason_reference": "safe_reference"})
        assert result.status_code == 201
