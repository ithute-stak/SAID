"""No device entitlements can be granted by citizen-link consent."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

@contextmanager
def citizen(subject: str, roles=frozenset({"citizen"}), institution="citizens"):
    actor = Principal(subject=subject, roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal", return_value=actor), patch(
        "said.protect.current_principal", return_value=actor
    ):
        yield

def inquire(category="ownership_inquiry"):
    reference = "LINK_" + uuid.uuid4().hex
    return client.post("/api/v1/protect/requests", json={
        "category": category, "device_reference": reference
    })

def create_intent(inquiry_id: str, consent=True, consent_version="SAID-LINK-CONSENT-v1"):
    return client.post("/api/v1/protect/link-intents", json={
        "inquiry_id": inquiry_id, "consent": consent,
        "consent_version": consent_version
    })

def test_link_consent_lifecycle_and_separation():
    with citizen("phase9-citizen-a"):
        inquiry = inquire()
        assert inquiry.status_code == 201, inquiry.text
        inquiry_id = inquiry.json()["id"]
        assert create_intent(inquiry_id, False).status_code == 422
        assert create_intent(inquiry_id, True, "unknown-version").status_code == 422
        created = create_intent(inquiry_id)
        assert created.status_code == 201, created.text
        intent = created.json()
        assert intent["status"] == "awaiting_independent_verification"
        assert "device_id" not in intent
        assert "imei" not in created.text.lower()
        assert "ownership_verified" not in created.text.lower()
        intent_id = intent["id"]
        assert create_intent(inquiry_id).status_code == 409
        result = client.get("/api/v1/protect/link-intents")
        assert result.status_code == 200
        assert intent_id in [i["id"] for i in result.json()]
    with citizen("phase9-citizen-b"):
        assert create_intent(inquiry_id).status_code == 404
        assert client.get("/api/v1/protect/link-intents/" + intent_id).status_code == 404
        assert client.post("/api/v1/protect/link-intents/" + intent_id + "/withdraw").status_code == 404
        assert intent_id not in [i["id"] for i in client.get("/api/v1/protect/link-intents").json()]
    with citizen("phase9-citizen-a"):
        withdrawn = client.post("/api/v1/protect/link-intents/" + intent_id + "/withdraw")
        assert withdrawn.status_code == 200
        assert withdrawn.json()["status"] == "withdrawn"
        assert client.post("/api/v1/protect/link-intents/" + intent_id + "/withdraw").status_code == 404
        assert client.get("/api/v1/protect/link-intents/" + intent_id).json()["status"] == "withdrawn"

def test_non_ownership_inquiry_cannot_link():
    with citizen("phase9-citizen-c"):
        inquiry = inquire("lost_device_inquiry")
        assert inquiry.status_code == 201
        assert create_intent(inquiry.json()["id"]).status_code == 404

def test_role_and_institution_required():
    with citizen("phase9-citizen-d", institution="operator-a"):
        assert client.get("/api/v1/protect/link-intents").status_code == 403
    with citizen("phase9-citizen-d", roles=frozenset({"said_admin"})):
        assert client.get("/api/v1/protect/link-intents").status_code == 403
    assert client.get("/api/v1/protect/link-intents").status_code == 401
