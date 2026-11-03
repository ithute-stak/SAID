"""Q.5055-informed CEIR sandbox must never take an operational network action."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal
from said.main import validate_imei

client = TestClient(app)

@contextmanager
def actor(institution: str, roles: set[str]):
    p = Principal(subject="ceir-test-" + uuid.uuid4().hex,
                  roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal", return_value=p), patch(
        "said.ceir.api.current_principal", return_value=p
    ):
        yield

def valid_imei():
    stem = "356938035643" + str(uuid.uuid4().int % 100).zfill(2)
    for digit in "0123456789":
        try:
            return validate_imei(stem + digit)
        except ValueError:
            continue
    raise AssertionError("no valid check digit")

def register_device():
    return client.post("/api/v1/devices", json={
        "imei": valid_imei(), "owner_reference": "sandbox",
        "make": "Example", "model": "Simulator"})

def test_sandbox_permissions_and_no_network_actions():
    with actor("dealer-demo", {"registrar"}):
        registration = register_device()
        assert registration.status_code == 201, registration.text
        device_id = registration.json()["id"]
        assert client.post("/api/v1/ceir/sandbox/entries", json={"device_id": device_id}).status_code == 403

    with actor("said-central", {"said_admin"}):
        added = client.post("/api/v1/ceir/sandbox/entries", json={"device_id": device_id})
        assert added.status_code == 201, added.text
        entry = added.json()
        assert entry["sandbox_only"] is True
        assert entry["network_action_taken"] is False
        assert entry["proposed_status"] == "unassessed"
        assert client.post("/api/v1/ceir/sandbox/entries", json={"device_id": device_id}).status_code == 409

        url = "/api/v1/ceir/sandbox/entries/" + entry["id"]
        assert client.get(url).status_code == 200
        invalid = client.post(url + "/propose", json={
            "proposed_status": "blocked", "reason_reference": "testcase", "expected_revision": 1})
        assert invalid.status_code == 422
        valid = client.post(url + "/propose", json={
            "proposed_status": "proposed_blocked", "reason_reference": "case_test_123",
            "expected_revision": 1})
        assert valid.status_code == 200, valid.text
        assert valid.json()["revision"] == 2
        assert valid.json()["network_action_taken"] is False
        stale = client.post(url + "/propose", json={
            "proposed_status": "proposed_permitted", "reason_reference": "case_test_124",
            "expected_revision": 1})
        assert stale.status_code == 409
        events = client.get(url + "/events")
        assert events.status_code == 200
        assert [e["proposed_status"] for e in events.json()] == ["unassessed", "proposed_blocked"]

    with actor("operator-a", {"said_admin"}):
        assert client.get(url).status_code == 403
        assert client.post(url + "/propose", json={
            "proposed_status": "proposed_tracked", "reason_reference": "test_125",
            "expected_revision": 2}).status_code == 403
    assert client.get(url).status_code == 401
