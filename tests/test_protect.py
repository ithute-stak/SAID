"""Citizen requests must be subject-scoped even inside the citizen institution."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

@contextmanager
def citizen(subject: str, institution="citizens", roles=frozenset({"citizen"})):
    actor = Principal(subject=subject, institution=institution, roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=actor), patch(
        "said.protect.current_principal", return_value=actor
    ):
        yield

def test_citizen_can_only_see_own_inquiries():
    ref = uuid.uuid4().hex
    with citizen("citizen-1"):
        made = client.post("/api/v1/protect/requests", json={
            "category":"lost_device_inquiry", "device_reference":"MY_CASE_"+ref})
        assert made.status_code == 201, made.text
        row_id = made.json()["id"]
        assert made.json()["status"] == "pending_manual_review"
        own = client.get("/api/v1/protect/requests")
        assert own.status_code == 200
        assert any(x["id"] == row_id for x in own.json())

    with citizen("citizen-2"):
        assert client.get("/api/v1/protect/requests/"+row_id).status_code == 404
        assert all(x["id"] != row_id for x in client.get("/api/v1/protect/requests").json())
        assert client.post("/api/v1/protect/requests", json={
            "category":"device_enrollment_inquiry", "device_reference":"SAFE_REF",
            "citizen_subject":"citizen-1"}).status_code == 201

    with citizen("citizen-1"):
        assert client.get("/api/v1/protect/requests/"+row_id).status_code == 200

def test_citizen_role_and_institution_both_required():
    with citizen("someone", institution="operator-a"):
        assert client.get("/api/v1/protect/requests").status_code == 403
    with citizen("someone", roles={"registrar"}):
        assert client.get("/api/v1/protect/requests").status_code == 403
    with citizen("development-admin", institution="development-only",
                 roles={"said_admin", "citizen"}):
        assert client.get("/api/v1/protect/requests").status_code == 403
    assert client.get("/api/v1/protect/requests").status_code == 401

def test_intake_rejects_imei_national_id_and_other_pii_shaped_references():
    with citizen("citizen-valid"):
        for reference in ("490154203237518", "123456789", "some thing", "A/B"):
            answer = client.post("/api/v1/protect/requests", json={
                "category":"device_enrollment_inquiry",
                "device_reference":reference})
            if reference.isdigit():
                # Unambiguous numeric identifiers are rejected as potentially
                # IMEI / National ID / phone numbers.
                assert answer.status_code == 422
            else:
                assert answer.status_code == 422

def test_protect_page_is_branded_and_data_api_restricted():
    page = client.get("/protect/")
    assert page.status_code == 200
    assert "SAID Protect" in page.text
    assert "Powered by" in page.text
    assert "Content-Security-Policy" in page.headers
    assert client.get("/console/static/protect.js").status_code == 200
    assert client.get("/console/static/protect.css").status_code == 200
    assert "Ownership-link consent" in page.text
    assert "No device has been linked" in client.get("/console/static/protect.js").text
    js = client.get("/console/static/protect.js").text
    for forbidden in ("localStorage", "sessionStorage", "document.cookie", "X-Admin-Key"):
        assert forbidden not in js
