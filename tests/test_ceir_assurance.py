"""Phase 18 sandbox assurance: independent approvals and export-only manifests."""
import uuid
from contextlib import contextmanager
from unittest.mock import patch

from fastapi.testclient import TestClient
from said.main import app
from said.security import Principal

client = TestClient(app)
ROOT = "/api/v1/ceir/sandbox"

@contextmanager
def actor(subject, roles=("said_admin",), institution="said-central"):
    p = Principal(subject=subject, roles=frozenset(roles), institution=institution)
    with patch("said.main.current_principal", return_value=p), patch(
        "said.ceir.api.current_principal", return_value=p
    ):
        yield

def create_reviewed_case(monkeypatch):
    monkeypatch.setenv("SAID_CEIR_HMAC_KEY", "synthetic-phase18-secret-key-123456789")
    with actor("phase18-opener"):
        observation = client.post(ROOT + "/quality/observations", json={
            "source_code": "mock_operator_alpha",
            "reference": "PH18_" + uuid.uuid4().hex,
            "imei": "490154203237518"
        })
        assert observation.status_code == 201, observation.text
        opened = client.post(ROOT + "/quality/observations/" +
                             observation.json()["id"] + "/investigation")
        assert opened.status_code == 201, opened.text
        case_id = opened.json()["id"]
    with actor("phase18-reviewer", ("said_admin", "ceir_reviewer")):
        reviewed = client.post(ROOT + "/quality/investigations/" +
                               case_id + "/review", json={
            "decision": "insufficient_evidence",
            "decision_reference": "phase18_review_001"
        })
        assert reviewed.status_code == 200, reviewed.text
    return case_id

def test_manifest_and_independent_retention_approval(monkeypatch):
    case_id = create_reviewed_case(monkeypatch)
    with actor("phase18-auditor", ("said_admin", "ceir_auditor")):
        checkpoint = client.post(ROOT + "/oversight/checkpoints", json={
            "investigation_id": case_id, "reason_reference": "audit_phase18"
        })
        assert checkpoint.status_code == 201, checkpoint.text
        checkpoint_id = checkpoint.json()["id"]
        manifest = client.get(ROOT + "/assurance/checkpoints/" +
                              checkpoint_id + "/manifest")
        assert manifest.status_code == 200, manifest.text
        data = manifest.json()
        assert data["manifest"]["investigation_id"] == case_id
        assert len(data["manifest_sha256"]) == 64
        assert data["signed"] is False
        assert data["transmitted"] is False
        assert data["externally_anchored"] is False
        assert data["export_preparation_only"] is True
        assert "imei" not in manifest.text.lower()
        assert client.get(ROOT + "/assurance/checkpoints/" +
                          checkpoint_id + "/manifest").json()["manifest_sha256"] == data["manifest_sha256"]
    with actor("phase18-opener", ("said_admin", "ceir_supervisor")):
        assert client.post(ROOT + "/assurance/retention-plans", json={
            "investigation_id": case_id, "rationale_reference": "retain_001"
        }).status_code == 403
    with actor("phase18-supervisor", ("said_admin", "ceir_supervisor")):
        requested = client.post(ROOT + "/assurance/retention-plans", json={
            "investigation_id": case_id, "rationale_reference": "retain_001"
        })
        assert requested.status_code == 201, requested.text
        plan_id = requested.json()["id"]
        assert requested.json()["execution_enabled"] is False
        assert requested.json()["records_deleted"] == 0
        assert client.post(ROOT + "/assurance/retention-plans", json={
            "investigation_id": case_id, "rationale_reference": "retain_002"
        }).status_code == 409
    endpoint = ROOT + "/assurance/retention-plans/" + plan_id + "/decide"
    decision = {"decision": "approve_plan", "approval_reference": "independent_002"}
    with actor("phase18-supervisor", ("said_admin", "ceir_retention_approver")):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("phase18-reviewer", ("said_admin", "ceir_retention_approver")):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("phase18-approver", ("said_admin",)):
        assert client.post(endpoint, json=decision).status_code == 403
    with actor("phase18-approver", ("said_admin", "ceir_retention_approver")):
        approved = client.post(endpoint, json=decision)
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved_plan_only"
        assert approved.json()["execution_enabled"] is False
        assert approved.json()["records_deleted"] == 0
        assert client.post(endpoint, json=decision).status_code == 409
        listing = client.get(ROOT + "/assurance/retention-plans")
        assert plan_id in [row["id"] for row in listing.json()]
        chain = client.get(ROOT + "/governance/investigations/" +
                           case_id + "/integrity")
        assert chain.status_code == 200
        assert chain.json()["valid"] is True
        assert chain.json()["events_checked"] == 4

def test_active_hold_fails_closed(monkeypatch):
    case_id = create_reviewed_case(monkeypatch)
    with actor("phase18-other-supervisor", ("said_admin", "ceir_supervisor")):
        held = client.post(ROOT + "/oversight/holds", json={
            "investigation_id": case_id, "reason_reference": "legal_hold_001"
        })
        assert held.status_code == 201, held.text
        blocked = client.post(ROOT + "/assurance/retention-plans", json={
            "investigation_id": case_id, "rationale_reference": "retention_001"
        })
        assert blocked.status_code == 409

def test_assurance_rejects_unauthorized():
    assert client.get(ROOT + "/assurance/retention-plans").status_code == 401
    with actor("foreign", ("said_admin", "ceir_retention_approver"), "operator-test"):
        assert client.get(ROOT + "/assurance/retention-plans").status_code == 403
    with actor("central-ordinary-admin"):
        assert client.get(ROOT + "/assurance/retention-plans").status_code == 403
