"""Phase 24: deployment, recovery and incident assessment fail closed."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from audit_authority.authority import open_store, issue
from audit_authority.readiness import (
    check_unit, assess_objectives, assess_incident, readiness_report,
)

UNIT = Path(__file__).resolve().parents[1] / "deploy/audit-authority/said-audit-drill.service.example"
MANIFEST = {
    "schema": "said.mock.audit-checkpoint.v1",
    "checkpoint_id": "a1111111-1111-4111-8111-111111111111",
    "investigation_id": "b2222222-2222-4222-8222-222222222222",
    "sequence": 1, "head_digest": "a" * 64,
    "checkpoint_digest": "b" * 64, "reason_reference": "readiness_case_01",
}
OBJECTIVES = {
    "recovery_time_objective_minutes": 60,
    "recovery_point_objective_minutes": 120,
    "observed_recovery_duration_seconds": 1200,
    "observed_backup_age_seconds": 3600,
    "recovery_test_passed": True,
    "backup_integrity_passed": True,
}
INCIDENT = {
    "scenario": "receipt_store_corruption",
    "evidence_preserved": True, "signing_suspended": True,
    "independent_reviewer_assigned": True,
    "escalation_reference": "case_2026_11_001",
}

def test_sample_deployment_unit_and_unsafe_variants(tmp_path):
    assert check_unit(str(UNIT))["passed"] is True
    original = UNIT.read_text()
    path = tmp_path / "unit.service"
    path.write_text(original.replace("NoNewPrivileges=true", "NoNewPrivileges=false"))
    result = check_unit(str(path))
    assert result["passed"] is False
    assert "unexpected_NoNewPrivileges" in result["issues"]
    path.write_text(original + "\nEnvironment=AUDIT_AUTHORITY_PASSPHRASE=secret\n")
    assert "environment_secrets_not_allowed" in check_unit(str(path))["issues"]
    path.write_text(original.replace("IPAddressDeny=any", "IPAddressDeny=none"))
    assert check_unit(str(path))["passed"] is False
    path.write_text(original.replace("ReadWritePaths=/var/lib/said-audit/drills",
                                     "ReadWritePaths=/var/lib/said-audit/drills /var/lib/said-audit/receipts.db"))
    assert "unexpected_writable_path" in check_unit(str(path))["issues"]
    assert check_unit(str(tmp_path / "absent.service"))["passed"] is False

def test_recovery_objectives_and_incident_exercise():
    passed = assess_objectives(OBJECTIVES)
    assert passed["passed"] is True
    assert passed["measurements_operator_supplied"] is True
    assert assess_objectives({**OBJECTIVES, "observed_recovery_duration_seconds": 6000})["passed"] is False
    assert assess_objectives({**OBJECTIVES, "observed_backup_age_seconds": 9000})["rpo_met"] is False
    assert assess_objectives({**OBJECTIVES, "backup_integrity_passed": False})["passed"] is False
    with pytest.raises(Exception):
        assess_objectives({**OBJECTIVES, "recovery_time_objective_minutes": -10})
    assert assess_incident(INCIDENT)["passed"] is True
    failure = assess_incident({**INCIDENT, "signing_suspended": False})
    assert failure["passed"] is False
    assert failure["actions_executed"] is False
    with pytest.raises(Exception):
        assess_incident({**INCIDENT, "scenario": "live_carrier_blocking"})

def test_full_readiness_requires_existing_healthy_store(tmp_path):
    path = tmp_path / "authority.db"
    db = open_store(str(path))
    try:
        issue(db, MANIFEST, "test-audit-key", Ed25519PrivateKey.generate())
    finally:
        db.close()
    good = readiness_report(str(UNIT), str(path), OBJECTIVES, INCIDENT)
    assert good["passed"] is True
    assert good["production_approval_granted"] is False
    assert good["external_audit_verified"] is False
    assert readiness_report(str(UNIT), str(tmp_path / "missing.db"), OBJECTIVES, INCIDENT)["passed"] is False
    bad = readiness_report(str(UNIT), str(path), OBJECTIVES,
                           {**INCIDENT, "evidence_preserved": False})
    assert bad["passed"] is False
    assert path.is_file()
