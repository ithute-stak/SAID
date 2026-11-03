"""SAID Control: public shell, private API, same-origin static assets."""
from fastapi.testclient import TestClient
from said.main import app

client = TestClient(app)

def test_console_shell_and_security_headers():
    response = client.get("/console/")
    assert response.status_code == 200
    assert "SAID" in response.text
    assert "Powered by Ithute" in response.text
    assert "not a citizen account portal" in response.text
    assert "Content-Security-Policy" in response.headers
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"

def test_console_static_assets_are_available_without_external_dependencies():
    for name, media in [
        ("style.css", "text/css"),
        ("app.js", "javascript"),
    ]:
        response = client.get("/console/static/" + name)
        assert response.status_code == 200
        assert media in response.headers["content-type"]

def test_console_does_not_bypass_protected_api():
    assert client.get("/api/v1/devices/any-id").status_code == 401
    assert client.post("/api/v1/devices", json={}).status_code == 401
    assert client.get("/api/v1/ownership/claims/any-id").status_code == 401

def test_no_client_side_credential_persistence():
    script = client.get("/console/static/app.js").text
    for unsafe in ("localStorage", "sessionStorage", "document.cookie", "X-Admin-Key"):
        assert unsafe not in script
    assert 'credentials: "omit"' in script
