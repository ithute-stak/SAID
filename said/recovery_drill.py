"""Phase 39: evaluate synthetic disaster-recovery drill evidence, read only.

This evaluates a supplied record of an ALREADY COMPLETED, ISOLATED restore.
It neither connects to a database nor initiates a backup or restore.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RecoveryDrill(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.recovery-drill.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    recovery_target: Literal["isolated_disposable_staging"]
    source: Literal["synthetic_nonproduction"]
    backup_id: str = Field(min_length=8, max_length=128,
                           pattern=r"^[A-Za-z0-9_.-]+$")
    backup_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    downloaded_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    restore_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    backup_point_at: datetime = Field(strict=False)
    incident_at: datetime = Field(strict=False)
    restored_at: datetime = Field(strict=False)
    target_rpo_seconds: int = Field(ge=0, le=86400)
    target_rto_seconds: int = Field(gt=0, le=604800)
    schema_migrations_valid: bool
    foreign_keys_valid: bool
    row_counts_valid: bool
    audit_chain_valid: bool
    restored_with_nonprivileged_role: bool
    telecom_egress_disabled: bool
    independent_witness_reference: str = Field(
        min_length=8, max_length=180, pattern=r"^[A-Za-z0-9_.:/#-]+$")

    @model_validator(mode="after")
    def all_datetimes_tzaware(self):
        for field in ("backup_point_at", "incident_at", "restored_at"):
            if getattr(self, field).tzinfo is None:
                raise ValueError(field + " requires timezone")
        return self


def assess_drill(raw: dict, *, now: datetime | None = None) -> dict:
    drill = RecoveryDrill.model_validate(raw)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Assessment time requires timezone")
    issues = []
    for name in ("backup_sha256", "downloaded_sha256"):
        if getattr(drill, name) != drill.backup_sha256:
            issues.append("backup_checksum_mismatch")
    if drill.restore_snapshot_sha256 != drill.expected_snapshot_sha256:
        issues.append("restored_snapshot_checksum_mismatch")
    if not drill.backup_point_at <= drill.incident_at <= drill.restored_at <= current:
        issues.append("invalid_recovery_timeline")
    rpo = max(0, int((drill.incident_at - drill.backup_point_at).total_seconds()))
    rto = max(0, int((drill.restored_at - drill.incident_at).total_seconds()))
    if rpo > drill.target_rpo_seconds:
        issues.append("rpo_target_exceeded")
    if rto > drill.target_rto_seconds:
        issues.append("rto_target_exceeded")
    for name in ("schema_migrations_valid", "foreign_keys_valid", "row_counts_valid",
                 "audit_chain_valid", "restored_with_nonprivileged_role",
                 "telecom_egress_disabled"):
        if getattr(drill, name) is not True:
            issues.append(name + "_not_verified")
    if (current - drill.restored_at).total_seconds() > 30 * 86400:
        issues.append("recovery_drill_stale")
    report = {
        "schema": "said.mock.recovery-assessment.v1",
        "commit_sha": drill.commit_sha,
        "backup_id": drill.backup_id,
        "declared_recovery_checks_passed": not issues,
        "measured_rpo_seconds_from_report": rpo,
        "measured_rto_seconds_from_report": rto,
        "issues": sorted(set(issues)),
        "restore_executed_by_assessor": False,
        "backup_bytes_read_by_assessor": False,
        "independent_witness_authenticated": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    report["sha256"] = hashlib.sha256(json.dumps(
        report, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="Evaluate offline synthetic SAID recovery evidence")
    parser.add_argument("--drill", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = assess_drill(json.loads(args.drill.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print(json.dumps({"declared_recovery_checks_passed": False,
                          "error_type": type(exc).__name__,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["declared_recovery_checks_passed"] else 2)


if __name__ == "__main__":
    main()
