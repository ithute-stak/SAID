"""Local audit checkpoints, independent preservation holds and restricted oversight."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch
from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client=TestClient(app)
BASE="/api/v1/ceir/sandbox"

@contextmanager
def actor(subject, roles=("said_admin",), institution="said-central"):
    principal=Principal(subject=subject, roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal",return_value=principal),patch(
        "said.ceir.api.current_principal",return_value=principal):
        yield

def make_case(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY","phase17-only-fake-key-12345678987654")
    with actor("opener"):
        response=client.post(BASE+"/quality/observations",json={
            "source_code":"mock_operator_alpha",
            "reference":"OVERSIGHT_"+uuid.uuid4().hex,
            "imei":"490154203237518"})
        assert response.status_code==201,response.text
        opened=client.post(BASE+"/quality/observations/"+
                           response.json()["id"]+"/investigation")
        assert opened.status_code==201,opened.text
        return opened.json()["id"]

def test_checkpoint_and_preservation_hold(monkeypatch):
    case_id=make_case(monkeypatch)
    params={"investigation_id":case_id,"reason_reference":"AUDIT_001"}
    with actor("opener",("said_admin","ceir_auditor","ceir_supervisor")):
        assert client.post(BASE+"/oversight/checkpoints",json=params).status_code==403
        assert client.post(BASE+"/oversight/holds",json=params).status_code==403
    with actor("auditor",("said_admin","ceir_auditor")):
        checkpoint=client.post(BASE+"/oversight/checkpoints",json=params)
        assert checkpoint.status_code==201,checkpoint.text
        data=checkpoint.json()
        assert data["externally_anchored"] is False
        assert data["reason_reference"]=="AUDIT_001"
        repeated=client.post(BASE+"/oversight/checkpoints",json=params)
        assert repeated.status_code==201
        assert repeated.json()["id"]==data["id"]
        verify=client.get(BASE+"/oversight/checkpoints/"+case_id)
        assert verify.status_code==200,verify.text
        assert verify.json()["valid"] is True
        assert verify.json()["checkpoints"]==1
        assert client.get(BASE+"/oversight/summary").status_code==200
        assert client.post(BASE+"/oversight/holds",json=params).status_code==403
    with actor("supervisor",("said_admin","ceir_supervisor")):
        hold=client.post(BASE+"/oversight/holds",json=params)
        assert hold.status_code==201,hold.text
        assert hold.json()["records_deleted"]==0
        assert client.post(BASE+"/oversight/holds",json=params).status_code==409
        assert any(x["investigation_id"]==case_id
                   for x in client.get(BASE+"/oversight/holds").json())
        summary=client.get(BASE+"/oversight/summary")
        assert summary.json()["active_holds_in_page"]>=1

def test_oversight_api_and_ui_security():
    assert client.get(BASE+"/oversight/summary").status_code==401
    with actor("foreign",("said_admin","ceir_supervisor"),"operator-test"):
        assert client.get(BASE+"/oversight/summary").status_code==403
    with actor("plain-admin"):
        assert client.get(BASE+"/oversight/summary").status_code==403
    page=client.get("/oversight/")
    assert page.status_code==200
    assert "Powered by Ithute" in page.text
    assert "default-src 'none'" in page.headers["Content-Security-Policy"]
    assert page.headers["Cache-Control"]=="no-store"
    assert "externally" not in page.headers.get("Server","")
    script=client.get("/console/static/oversight.js")
    assert script.status_code==200
    for forbidden in ("localStorage","sessionStorage","document.cookie","innerHTML","X-Admin-Key"):
        assert forbidden not in script.text
    assert 'credentials:"omit"' in script.text
