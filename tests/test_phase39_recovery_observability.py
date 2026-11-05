"""Phase 39: offline fault and recovery policy tests; no real backup access."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from said.recovery_drill import assess_drill
from said.observability_gate import assess_observability


def recovery():
    now = datetime.now(timezone.utc)
    return {
        "schema": "said.mock.recovery-drill.v1",
        "commit_sha": "a" * 40,
        "recovery_target": "isolated_disposable_staging",
        "source": "synthetic_nonproduction",
        "backup_id": "synthetic-backup-001",
        "backup_sha256": "a" * 64,
        "downloaded_sha256": "a" * 64,
        "restore_snapshot_sha256": "b" * 64,
        "expected_snapshot_sha256": "b" * 64,
        "backup_point_at": (now - timedelta(minutes=20)).isoformat(),
        "incident_at": (now - timedelta(minutes=10)).isoformat(),
        "restored_at": (now - timedelta(minutes=2)).isoformat(),
        "target_rpo_seconds": 900,
        "target_rto_seconds": 600,
        "schema_migrations_valid": True,
        "foreign_keys_valid": True,
        "row_counts_valid": True,
        "audit_chain_valid": True,
        "restored_with_nonprivileged_role": True,
        "telecom_egress_disabled": True,
        "independent_witness_reference": "staging/witness/001",
    }


def monitor():
    now = datetime.now(timezone.utc)
    return {
        "schema": "said.mock.observability.v1",
        "commit_sha": "a" * 40,
        "source": "synthetic_nonproduction",
        "observed_at": (now - timedelta(minutes=1)).isoformat(),
        "last_successful_backup_at": (now - timedelta(hours=1)).isoformat(),
        "last_successful_recovery_drill_at": (now - timedelta(days=1)).isoformat(),
        "api_requests": 500,
        "api_errors": 2,
        "api_p95_latency_ms": 600,
        "application_healthy": True,
        "database_healthy": True,
        "audit_verification_healthy": True,
        "security_events_unacknowledged": 0,
        "alerts_route_verified": True,
    }


def test_recovery_pass_is_only_reported_evidence():
    report = assess_drill(recovery())
    assert report["declared_recovery_checks_passed"]
    assert report["measured_rpo_seconds_from_report"] == 600
    assert report["measured_rto_seconds_from_report"] == 480
    assert not report["restore_executed_by_assessor"]
    assert not report["independent_witness_authenticated"]
    assert not report["staging_deploy_authorized"]
    assert len(report["sha256"]) == 64


@pytest.mark.parametrize("change,issue", [
    ({"downloaded_sha256": "c" * 64}, "backup_checksum_mismatch"),
    ({"restore_snapshot_sha256": "d" * 64}, "restored_snapshot_checksum_mismatch"),
    ({"target_rpo_seconds": 100}, "rpo_target_exceeded"),
    ({"target_rto_seconds": 100}, "rto_target_exceeded"),
    ({"audit_chain_valid": False}, "audit_chain_valid_not_verified"),
    ({"foreign_keys_valid": False}, "foreign_keys_valid_not_verified"),
    ({"restored_with_nonprivileged_role": False}, "restored_with_nonprivileged_role_not_verified"),
    ({"telecom_egress_disabled": False}, "telecom_egress_disabled_not_verified"),
])
def test_recovery_faults_fail_closed(change, issue):
    record = recovery()
    record.update(change)
    assert issue in assess_drill(record)["issues"]


def test_real_production_source_and_extra_authorization_rejected():
    record = recovery()
    record["source"] = "production"
    with pytest.raises(ValidationError):
        assess_drill(record)
    record = recovery()
    record["production_deploy_authorized"] = True
    with pytest.raises(ValidationError):
        assess_drill(record)


def test_recovery_bad_timeline_and_timezone_rejected():
    record = recovery()
    record["backup_point_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert "invalid_recovery_timeline" in assess_drill(record)["issues"]
    record = recovery()
    record["incident_at"] = "2026-11-05T08:00:00"
    with pytest.raises(ValidationError):
        assess_drill(record)


def test_monitor_success_remains_offline():
    report = assess_observability(monitor())
    assert report["declared_telemetry_healthy"]
    assert not report["snapshot_collected_by_assessor"]
    assert not report["alert_route_exercised_by_assessor"]
    assert not report["production_deploy_authorized"]


@pytest.mark.parametrize("change,issue", [
    ({"api_requests": 0}, "insufficient_api_samples"),
    ({"api_errors": 10}, "api_error_rate_over_1_percent"),
    ({"api_p95_latency_ms": 2500}, "api_latency_p95_over_1500ms"),
    ({"database_healthy": False}, "database_healthy_not_verified"),
    ({"audit_verification_healthy": False}, "audit_verification_healthy_not_verified"),
    ({"security_events_unacknowledged": 1}, "unacknowledged_security_events"),
    ({"alerts_route_verified": False}, "alerts_route_verified_not_verified"),
])
def test_observability_alert_scenarios(change, issue):
    record = monitor()
    record.update(change)
    assert issue in assess_observability(record)["issues"]


def test_monitor_stale_backup_and_telemetry():
    record = monitor()
    record["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    assert "telemetry_stale_or_future" in assess_observability(record)["issues"]
    record = monitor()
    record["last_successful_backup_at"] = (
        datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    assert "backup_missing_or_stale" in assess_observability(record)["issues"]


def test_monitor_cannot_claim_real_data_collection_or_deployment():
    record = monitor()
    record["source"] = "production"
    with pytest.raises(ValidationError):
        assess_observability(record)
    record = monitor()
    record["production_deploy_authorized"] = True
    with pytest.raises(ValidationError):
        assess_observability(record)
