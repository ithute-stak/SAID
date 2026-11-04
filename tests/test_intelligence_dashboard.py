"""SAID Intelligence dashboard: public shell, protected data APIs."""
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)

@contextmanager
def actor(institution, roles):
    principal = Principal(subject="intelligence-ui-test", institution=institution,
                          roles=frozenset(roles))
    with patch("said.main.current_principal", return_value=principal), patch(
        "said.ceir.api.current_principal", return_value=principal
    ):
        yield

def test_intelligence_shell_and_headers():
    page = client.get("/intelligence/")
    assert page.status_code == 200
    assert "SAID Intelligence" in page.text
    assert "Powered by Ithute" in page.text
    assert "Simulation only" in page.text
    assert page.headers["Cache-Control"] == "no-store"
    assert "default-src 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in page.headers["Content-Security-Policy"]
    assert "SAID Intelligence" in client.get("/console/").text

def test_assets_and_browser_credential_controls():
    for name, fragment in (("intelligence.js", "javascript"),
                           ("intelligence.css", "text/css")):
        r = client.get("/console/static/" + name)
        assert r.status_code == 200
        assert fragment in r.headers["content-type"]
    js = client.get("/console/static/intelligence.js").text
    for forbidden in ("localStorage", "sessionStorage", "document.cookie",
                      "innerHTML", "X-Admin-Key", "window.open"):
        assert forbidden not in js
    assert 'credentials: "omit"' in js
    assert "network action taken" in js

def test_api_remains_central_only():
    path = "/api/v1/ceir/sandbox/intelligence/investigations"
    assert client.get(path).status_code == 401
    with actor("mock_operator_alpha", {"said_admin"}):
        assert client.get(path).status_code == 403
    with actor("said-central", {"said_admin"}):
        assert client.get(path).status_code == 200
    with actor("said-central", {"registrar"}):
        assert client.get(path).status_code == 403
