"""Cross-institution access must fail closed for every record endpoint."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

def imei_for(seed: int) -> str:
    stem = f"356938035643{seed:02d}"  # 14 digits
    for check in range(10):
        from said.main import validate_imei
        value = stem + str(check)
        try:
            return validate_imei(value)
        except ValueError:
            continue
    raise AssertionError("No check digit")

@contextmanager
def as_actor(institution: str, roles: set[str]):
    actor = Principal(subject=str(uuid.uuid4()), institution=institution, roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=actor), patch(
        "said.ownership.current_principal", return_value=actor
    ):
        yield actor

def register(imei: str):
    return client.post("/api/v1/devices", json={
        "imei": imei, "owner_reference": "opaque-test-owner",
        "make": "Test", "model": "Model"})

def test_institution_boundaries_for_device_case_and_claim():
    with as_actor("vodacom-test", {"registrar", "case_worker", "owner_reviewer"}):
        created = register(imei_for(41))
        assert created.status_code == 201, created.text
        did = created.json()["id"]
        report = client.post(f"/api/v1/devices/{did}/theft-reports",
                             json={"incident_reference": "TEST-CASE"})
        assert report.status_code == 201, report.text
        rid = report.json()["id"]
        claim = client.post("/api/v1/ownership/claims", json={
            "device_id": did, "applicant_reference": "test",
            "evidence_reference": "evidence-ref"})
        assert claim.status_code == 201, claim.text
        cid = claim.json()["id"]

    with as_actor("econet-test", {"registrar", "case_worker", "owner_reviewer"}):
        assert client.get(f"/api/v1/devices/{did}").status_code == 404
        assert client.post(f"/api/v1/devices/{did}/theft-reports",
                           json={"incident_reference": "guess"}).status_code == 404
        assert client.get(f"/api/v1/theft-reports/{rid}").status_code == 404
        assert client.post("/api/v1/ownership/claims", json={
            "device_id": did, "applicant_reference": "intruder",
            "evidence_reference": "ref"}).status_code == 404
        assert client.get(f"/api/v1/ownership/claims/{cid}").status_code == 404
        assert client.post(f"/api/v1/ownership/claims/{cid}/review",
                           json={"decision": "evidence_supported"}).status_code == 404

    with as_actor("vodacom-test", {"registrar", "case_worker", "owner_reviewer"}):
        assert client.get(f"/api/v1/devices/{did}").status_code == 200
        assert client.get(f"/api/v1/theft-reports/{rid}").status_code == 200
        reviewed = client.post(f"/api/v1/ownership/claims/{cid}/review",
                               json={"decision": "evidence_supported"})
        assert reviewed.status_code == 200, reviewed.text
        assert reviewed.json()["identity_verified"] is False

def test_role_only_admin_cannot_cross_boundary():
    with as_actor("dealer-a", {"registrar"}):
        created = register(imei_for(42))
        assert created.status_code == 201
        did = created.json()["id"]
    with as_actor("dealer-b", {"said_admin", "owner_reviewer", "case_worker", "registrar"}):
        assert client.get(f"/api/v1/devices/{did}").status_code == 404
    with as_actor("said-central", {"said_admin"}):
        assert client.get(f"/api/v1/devices/{did}").status_code == 200
    with as_actor("dealer-a", {"case_worker"}):
        assert register(imei_for(43)).status_code == 403

def test_institution_from_claim_not_request_payload():
    with as_actor("dealer-a", {"registrar"}):
        made = client.post("/api/v1/devices", json={
            "imei": imei_for(44), "owner_reference": "owner", "make": "A",
            "model": "B", "institution_id": "dealer-b"})
        assert made.status_code == 201
        did = made.json()["id"]
    with as_actor("dealer-b", {"registrar"}):
        assert client.get(f"/api/v1/devices/{did}").status_code == 404
