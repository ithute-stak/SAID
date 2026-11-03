import os
import tempfile
from fastapi.testclient import TestClient

_tmp = tempfile.mkdtemp(prefix="said-test-")
os.environ["SAID_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["SAID_ADMIN_API_KEY"] = "test-secret-that-is-at-least-32-characters"
from said.main import Base, app, engine, validate_imei

Base.metadata.create_all(bind=engine)
client = TestClient(app)
HEADERS = {"X-Admin-Key": os.environ["SAID_ADMIN_API_KEY"]}

def test_auth_and_health():
    assert client.get("/health").status_code == 200
    assert client.post("/api/v1/devices", json={}).status_code == 401

def test_device_and_theft_report():
    # Publicly documented IMEI test example with valid Luhn digit.
    imei = "490154203237518"
    data = {"imei": imei, "owner_reference": "example-owner-1", "make": "Example", "model": "Phone"}
    registered = client.post("/api/v1/devices", json=data, headers=HEADERS)
    assert registered.status_code == 201, registered.text
    payload = registered.json()
    assert payload["verification_status"] == "unverified"
    assert payload["imei_masked"].endswith("7518")
    assert imei not in registered.text
    assert client.post("/api/v1/devices", json=data, headers=HEADERS).status_code == 409
    report = client.post(f"/api/v1/devices/{payload['id']}/theft-reports", json={"incident_reference":"CASE-TEST"}, headers=HEADERS)
    assert report.status_code == 201
    assert report.json()["status"] == "reported_pending_review"
    assert client.get(f"/api/v1/theft-reports/{report.json()['id']}", headers=HEADERS).status_code == 200

def test_invalid_imei():
    assert client.post("/api/v1/devices", json={"imei":"123456789012345","owner_reference":"x","make":"Y","model":"Z"}, headers=HEADERS).status_code == 422

def test_ownership_review_is_not_identity_verification():
    device = client.post("/api/v1/devices", json={
        "imei": "490154203237518", "owner_reference": "example-owner-1",
        "make": "Example", "model": "Phone"}, headers=HEADERS)
    # Another test may already have created this device.
    if device.status_code == 409:
        import sqlalchemy
        from said.main import SessionLocal, Device
        with SessionLocal() as session:
            device_id = session.query(Device).filter_by(imei="490154203237518").one().id
    else:
        assert device.status_code == 201, device.text
        device_id = device.json()["id"]
    data = {"device_id": device_id, "applicant_reference": "person-a",
            "evidence_reference": "internal-file-123"}
    assert client.post("/api/v1/ownership/claims", json=data).status_code == 401
    response = client.post("/api/v1/ownership/claims", json=data, headers=HEADERS)
    assert response.status_code == 201, response.text
    claim = response.json()
    assert claim["status"] == "pending_review"
    assert claim["identity_verified"] is False
    assert "person-a" not in response.text
    assert client.post("/api/v1/ownership/claims", json=data, headers=HEADERS).status_code == 409
    review_url = f"/api/v1/ownership/claims/{claim['id']}/review"
    assert client.post(review_url, json={"decision":"verified"}, headers=HEADERS).status_code == 422
    review = client.post(review_url, json={"decision":"evidence_supported"}, headers=HEADERS)
    assert review.status_code == 200, review.text
    assert review.json()["identity_verified"] is False
    assert client.post(review_url, json={"decision":"evidence_rejected"}, headers=HEADERS).status_code == 409
    fetched = client.get(f"/api/v1/devices/{device_id}", headers=HEADERS)
    assert fetched.json()["verification_status"] == "unverified"
