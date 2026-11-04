"""Phase 25 security evidence is strict, non-executing and unsigned."""
from datetime import datetime, timezone, timedelta
import pytest

from audit_authority.host_evidence import evaluate_host_snapshot, evidence_digest
from audit_authority.readiness import HARDENING

def snapshot():
    return {
        "schema": "said.mock.host-snapshot.v1",
        "hostname_reference": "audit-host-test",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collected_by": "independent-inspector",
        "unit_properties": {
            **HARDENING, "RestrictAddressFamilies": "AF_UNIX",
            "ReadWritePaths": "/var/lib/said-audit/drills",
            "ReadOnlyPaths": "/var/lib/said-audit/receipts.db"},
        "service_account": "said-audit",
        "source_database_owner": "receipt-owner",
        "signing_key_owner": "independent-key-custodian",
        "audit_reviewer": "security-reviewer",
        "operator_account": "deployment-operator",
        "root_filesystem_readonly": True,
        "independent_host_declared": True,
        "immutable_offsite_backup_verified": True,
        "hsm_or_kms_verified": True,
    }

def test_snapshot_pass_requires_full_separation():
    raw = snapshot()
    good = evaluate_host_snapshot(raw)
    assert good["passed"] is True
    assert good["host_attested"] is False
    assert good["production_approval_granted"] is False
    signed = evidence_digest(raw, good)
    assert signed["signed"] is False
    assert signed["externally_anchored"] is False
    assert len(signed["sha256"]) == 64
    assert evidence_digest(raw, good)["sha256"] == signed["sha256"]

def test_snapshot_denied_and_missing_fields():
    raw = snapshot()
    fail = evaluate_host_snapshot({**raw, "signing_key_owner": "said-audit",
                                  "hsm_or_kms_verified": False,
                                  "immutable_offsite_backup_verified": False})
    assert not fail["passed"]
    assert "duties_not_separated" in fail["issues"]
    assert "signing_key_custody_unverified" in fail["issues"]
    assert "offsite_backup_unverified" in fail["issues"]
    assert not evaluate_host_snapshot({**raw, "unit_properties": {
        **raw["unit_properties"], "IPAddressDeny": "none"}})["passed"]
    stale = {**raw, "collected_at": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()}
    assert "snapshot_not_current" in evaluate_host_snapshot(stale)["issues"]
    naive = {**raw, "collected_at": "2026-11-04T07:00:00"}
    assert "snapshot_not_current" in evaluate_host_snapshot(naive)["issues"]
    with pytest.raises(Exception):
        evaluate_host_snapshot({**raw, "extra_secret": "should-fail"})
    with pytest.raises(Exception):
        evaluate_host_snapshot({k:v for k,v in raw.items() if k!="collected_by"})
