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
