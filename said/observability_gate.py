"""Phase 39 — Evaluate offline observability snapshots without collecting data.

No external monitoring API, host access or credentials. The operator must
provide synthetic or separately authorized telemetry; never real IMEI/PII.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class MonitorSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.observability.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    source: Literal["synthetic_nonproduction"]
    observed_at: datetime = Field(strict=False)
    last_successful_backup_at: datetime = Field(strict=False)
    last_successful_recovery_drill_at: datetime = Field(strict=False)
    api_requests: int = Field(ge=0)
    api_errors: int = Field(ge=0)
    api_p95_latency_ms: int = Field(ge=0, le=600000)
    application_healthy: bool
    database_healthy: bool
    audit_verification_healthy: bool
    security_events_unacknowledged: int = Field(ge=0)
    alerts_route_verified: bool


def assess_observability(raw: dict, *, now: datetime | None = None) -> dict:
    data = MonitorSnapshot.model_validate(raw)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Timezone-aware assessment required")
    issues = []
    for field in ("observed_at", "last_successful_backup_at",
                  "last_successful_recovery_drill_at"):
        if getattr(data, field).tzinfo is None:
            issues.append(field + "_not_timezone_aware")
    age = (current - data.observed_at).total_seconds()
    if not 0 <= age <= 600:
        issues.append("telemetry_stale_or_future")
    if not 0 <= (current - data.last_successful_backup_at).total_seconds() <= 86400:
        issues.append("backup_missing_or_stale")
    if not 0 <= (current - data.last_successful_recovery_drill_at).total_seconds() <= 30 * 86400:
        issues.append("recovery_drill_missing_or_stale")
    if data.api_errors > data.api_requests:
        issues.append("invalid_request_counters")
    if data.api_requests == 0:
        issues.append("insufficient_api_samples")
    elif data.api_errors * 100 > data.api_requests:
        issues.append("api_error_rate_over_1_percent")
    if data.api_p95_latency_ms > 1500:
        issues.append("api_latency_p95_over_1500ms")
    for name in ("application_healthy", "database_healthy",
                 "audit_verification_healthy", "alerts_route_verified"):
        if getattr(data, name) is not True:
            issues.append(name + "_not_verified")
    if data.security_events_unacknowledged > 0:
        issues.append("unacknowledged_security_events")
    report = {
        "schema": "said.mock.observability-assessment.v1",
        "commit_sha": data.commit_sha,
        "declared_telemetry_healthy": not issues,
        "issues": sorted(set(issues)),
        "snapshot_collected_by_assessor": False,
        "alert_route_exercised_by_assessor": False,
        "pii_or_imei_telemetry_collected": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    report["sha256"] = hashlib.sha256(json.dumps(
        report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="Evaluate offline synthetic SAID observability")
    parser.add_argument("--snapshot", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess_observability(json.loads(args.snapshot.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print(json.dumps({"declared_telemetry_healthy": False,
                          "error_type": type(exc).__name__,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["declared_telemetry_healthy"] else 2)


if __name__ == "__main__":
    main()
