"""Integrated Phase 40 fail-closed evidence tests; no live systems."""
from datetime import datetime, timedelta, timezone
import copy
import hashlib

import pytest
from pydantic import ValidationError

from said.evidence_chain import (
    ORDER, SCHEMA, DIGEST_FIELD, PASS_FIELD, build_chain, canonical,
)
from said.integrated_security import assess_integrated
from said.staging_security import REQUIRED_CONTROLS

SHA = "a" * 40


def fixture_bundle():
    current = datetime.now(timezone.utc)
    recovered = current - timedelta(hours=1)
    reports = {}
    for kind in ORDER:
        report = {
            "schema": SCHEMA[kind], "commit_sha": SHA, PASS_FIELD[kind]: True,
            "issues": [], "staging_deploy_authorized": False,
            "production_deploy_authorized": False,
            "telecom_operations_enabled": False,
        }
        report[DIGEST_FIELD[kind]] = hashlib.sha256(canonical(report)).hexdigest()
        reports[kind] = report
    chain = build_chain(SHA, reports)
    staging = {
        "schema": "said.mock.staging-security-input.v1",
        "commit_sha": SHA,
        "evidence_chain_root": chain["root_digest"],
        "evidence_chain_integrity_consistent": True,
        "staging_host_reference": "synthetic-staging-host-01",
        "controls": [{"name": name, "state": "verified",
                      "evidence_reference": "audit/check/" + name}
                     for name in REQUIRED_CONTROLS],
    }
    drill = {
        "schema": "said.mock.recovery-drill.v1",
        "commit_sha": SHA,
        "recovery_target": "isolated_disposable_staging",
        "source": "synthetic_nonproduction",
        "backup_id": "mock-backup-0001", "backup_sha256": "1" * 64,
        "downloaded_sha256": "1" * 64,
        "restore_snapshot_sha256": "2" * 64,
        "expected_snapshot_sha256": "2" * 64,
        "backup_point_at": (recovered - timedelta(minutes=20)).isoformat(),
        "incident_at": (recovered - timedelta(minutes=10)).isoformat(),
        "restored_at": recovered.isoformat(),
        "target_rpo_seconds": 1200,
        "target_rto_seconds": 1200,
        "schema_migrations_valid": True, "foreign_keys_valid": True,
        "row_counts_valid": True, "audit_chain_valid": True,
        "restored_with_nonprivileged_role": True,
        "telecom_egress_disabled": True,
        "independent_witness_reference": "test/witness/001",
    }
    telemetry = {
        "schema": "said.mock.observability.v1", "commit_sha": SHA,
        "source": "synthetic_nonproduction",
        "observed_at": (current - timedelta(seconds=20)).isoformat(),
        "last_successful_backup_at": (current - timedelta(minutes=30)).isoformat(),
        "last_successful_recovery_drill_at": recovered.isoformat(),
        "api_requests": 1000, "api_errors": 1,
        "api_p95_latency_ms": 450, "application_healthy": True,
        "database_healthy": True, "audit_verification_healthy": True,
        "security_events_unacknowledged": 0, "alerts_route_verified": True,
    }
    return {
        "schema": "said.mock.integrated-security-input.v1",
        "commit_sha": SHA, "release_chain": chain,
        "staging_snapshot": staging, "recovery_drill": drill,
        "observability_snapshot": telemetry,
    }


def test_integrated_synthetic_success_is_not_authorization():
    result = assess_integrated(fixture_bundle())
    assert result["integrated_checks_passed"], result["issues"]
    assert all(x["passed"] for x in result["components"].values())
    assert result["external_release_chain_anchor_verified"] is False
    assert result["operator_evidence_independently_authenticated"] is False
    assert result["actual_restore_executed"] is False
    assert result["actual_load_test_executed"] is False
    assert result["staging_deploy_authorized"] is False
    assert result["production_deploy_authorized"] is False
    assert len(result["sha256"]) == 64


@pytest.mark.parametrize("component,mutation,expected", [
    ("release_chain", lambda r: r.update(root_digest="f" * 64), "release_chain_failed"),
    ("staging_snapshot", lambda r: r["controls"].pop(), "staging_security_failed"),
    ("recovery_drill", lambda r: r.update(downloaded_sha256="f" * 64),
     "recovery_drill_failed"),
    ("observability_snapshot", lambda r: r.update(api_errors=800),
     "observability_failed"),
])
def test_each_component_failure_blocks_integrated_review(component, mutation, expected):
    data = fixture_bundle()
    mutation(data[component])
    result = assess_integrated(data)
    assert not result["integrated_checks_passed"]
    assert expected in result["issues"]


def test_incorrect_chain_root_link_blocks_review():
    data = fixture_bundle()
    data["staging_snapshot"]["evidence_chain_root"] = "f" * 64
    result = assess_integrated(data)
    assert "staging_release_root_mismatch" in result["issues"]


@pytest.mark.parametrize("component", [
    "release_chain", "staging_snapshot", "recovery_drill", "observability_snapshot",
])
def test_commit_substitution_detected(component):
    data = fixture_bundle()
    data[component]["commit_sha"] = "b" * 40
    result = assess_integrated(data)
    assert not result["integrated_checks_passed"]
    assert any("commit_mismatch" in x for x in result["issues"])


def test_recovery_and_monitoring_reference_different_drills():
    data = fixture_bundle()
    data["observability_snapshot"]["last_successful_recovery_drill_at"] = (
        datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()
    result = assess_integrated(data)
    assert "recovery_observability_drill_timestamp_mismatch" in result["issues"]


def test_invalid_child_evidence_does_not_crash_or_allow_review():
    data = fixture_bundle()
    data["recovery_drill"] = {"schema": "bad"}
    result = assess_integrated(data)
    assert "recovery_drill_invalid_evidence" in result["issues"]
    assert not result["integrated_checks_passed"]


def test_unknown_release_approval_cannot_be_inserted():
    data = fixture_bundle()
    data["production_deploy_authorized"] = True
    with pytest.raises(ValidationError):
        assess_integrated(data)


def test_rebuilt_unsigned_chain_still_not_authenticated():
    data = fixture_bundle()
    data["release_chain"]["entries"][1]["report"]["fabricated_approval"] = True
    from said.evidence_chain import checksum, build_chain
    reports = {entry["kind"]: copy.deepcopy(entry["report"])
               for entry in data["release_chain"]["entries"]}
    reports["pr"]["report_sha256"] = checksum(reports["pr"], "pr")
    data["release_chain"] = build_chain(SHA, reports)
    data["staging_snapshot"]["evidence_chain_root"] = data["release_chain"]["root_digest"]
    report = assess_integrated(data)
    assert report["integrated_checks_passed"]
    assert report["operator_evidence_independently_authenticated"] is False
    assert report["staging_deploy_authorized"] is False
