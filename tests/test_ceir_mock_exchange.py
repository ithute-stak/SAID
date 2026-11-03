"""Offline mock-only CEIR exchange smoke tests."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app, validate_imei
from said.security import Principal

client = TestClient(app)

@contextmanager
def actor(institution, roles):
    p = Principal(subject=uuid.uuid4().hex, institution=institution, roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=p), patch("said.ceir.api.current_principal", return_value=p):
        yield

_next_test_imei = 0

def sample_imei():
    global _next_test_imei
    _next_test_imei += 1
    base = "860000000000" + str(_next_test_imei).zfill(2)
    for d in "0123456789":
        try:
            return validate_imei(base + d)
        except ValueError:
            continue
    raise RuntimeError("No check digit")

def simulation():
    with actor("operator-test", {"registrar"}):
        r = client.post("/api/v1/devices", json={
            "imei": sample_imei(), "owner_reference": "test", "make": "Example", "model": "Test"})
        assert r.status_code == 201, r.text
        device = r.json()["id"]
    with actor("said-central", {"said_admin"}):
        r = client.post("/api/v1/ceir/sandbox/entries", json={"device_id": device})
        assert r.status_code == 201, r.text
        sid = r.json()["id"]
        r = client.post("/api/v1/ceir/sandbox/entries/" + sid + "/propose", json={
            "proposed_status": "proposed_tracked", "reason_reference": "case_test",
            "expected_revision": 1})
        assert r.status_code == 200, r.text
    return sid

def test_modes_and_retry():
    sid = simulation()
    with actor("said-central", {"said_admin"}):
        for mode in ("sync_api", "async_api", "periodic_file"):
            body = {"simulation_id": sid, "operator_code": "mock_operator_alpha", "mode": mode}
            first = client.post("/api/v1/ceir/sandbox/exchange/queue", json=body)
            assert first.status_code == 201, first.text
            row = first.json()
            assert row["external_transmission"] is False
            assert row["network_action_taken"] is False
            repeated = client.post("/api/v1/ceir/sandbox/exchange/queue", json=body)
            assert repeated.status_code == 201
            assert repeated.json()["id"] == row["id"]
            path = "/api/v1/ceir/sandbox/exchange/" + row["id"]
            failed = client.post(path + "/attempt", json={"simulate_failure": True})
            assert failed.status_code == 200
            assert failed.json()["state"] == "retry_pending"
            tried = client.post(path + "/attempt", json={"simulate_failure": False})
            assert tried.status_code == 200, tried.text
            assert tried.json()["attempt_count"] == 2
            if mode == "sync_api":
                assert tried.json()["state"] == "acknowledged"
            else:
                assert tried.json()["state"] == "awaiting_mock_ack"
                assert client.post(path + "/ack").json()["state"] == "acknowledged"
                assert client.post(path + "/ack").status_code == 409
            assert client.post(path + "/attempt", json={}).status_code == 409
            assert len(client.get(path + "/events").json()) >= 3
        report = client.get("/api/v1/ceir/sandbox/exchange/reconcile/mock_operator_beta")
        assert report.status_code == 200
        assert {"simulation_id": sid, "revision": 2} in report.json()["pending_revisions"]

def test_noncentral_access_forbidden():
    sid = simulation()
    with actor("operator-test", {"said_admin"}):
        assert client.post("/api/v1/ceir/sandbox/exchange/queue", json={
            "simulation_id": sid, "operator_code": "mock_operator_alpha",
            "mode": "sync_api"}).status_code == 403
