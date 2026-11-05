"""Phase 38: fail-closed OFFLINE staging security policy, without deployment.

Every input is operator-supplied, not measured independently. A passing
assessment is a checklist candidate, never permission to deploy.
"""
import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

REQUIRED_CONTROLS = (
    "environment_isolation",
    "nonproduction_data_only",
    "private_database_network",
    "restricted_database_role",
    "tls_at_ingress",
    "secrets_outside_repository",
    "restricted_admin_access",
    "service_resource_limits",
    "centralized_security_logging",
    "encrypted_backup",
    "restore_drill_verified",
    "incident_runbook_present",
    "mock_ceir_only",
    "telecom_egress_blocked",
)


class Control(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=3, max_length=80, pattern=r"^[a-z][a-z0-9_]+$")
    state: Literal["verified", "failed", "not_checked"]
    evidence_reference: str = Field(min_length=8, max_length=256,
                                    pattern=r"^[A-Za-z0-9_.:/#-]+$")


class StagingSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.staging-security-input.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    evidence_chain_root: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_chain_integrity_consistent: bool
    staging_host_reference: str = Field(min_length=8, max_length=128,
                                        pattern=r"^[A-Za-z0-9_.-]+$")
    controls: list[Control] = Field(min_length=1, max_length=30)


def assess_staging_security(raw: dict) -> dict:
    """Assess declared controls; refuse missing, duplicate and unknown values."""
    snapshot = StagingSnapshot.model_validate(raw)
    issues = []
    controls = {}
    for control in snapshot.controls:
        if control.name in controls:
            issues.append("duplicate_" + control.name)
        controls[control.name] = control
    unknown = sorted(set(controls) - set(REQUIRED_CONTROLS))
    issues.extend("unexpected_" + name for name in unknown)
    for name in REQUIRED_CONTROLS:
        if name not in controls:
            issues.append("missing_" + name)
        elif controls[name].state != "verified":
            issues.append("not_verified_" + name)
    if not snapshot.evidence_chain_integrity_consistent:
        issues.append("release_chain_integrity_not_confirmed")

    report = {
        "schema": "said.mock.staging-security-assessment.v1",
        "commit_sha": snapshot.commit_sha,
        "evidence_chain_root": snapshot.evidence_chain_root,
        "staging_host_reference": snapshot.staging_host_reference,
        "declared_controls_complete": not issues,
        "issues": sorted(set(issues)),
        "control_evidence_independently_authenticated": False,
        "host_configuration_remotely_measured": False,
        "trusted_release_chain_anchor_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    report["sha256"] = hashlib.sha256(json.dumps(
        report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="SAID offline staging security gate (no deploy)")
    parser.add_argument("--snapshot", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"))
        result = assess_staging_security(data)
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        print(json.dumps({"declared_controls_complete": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["declared_controls_complete"] else 2)


if __name__ == "__main__":
    main()
