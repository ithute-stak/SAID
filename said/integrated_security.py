"""SAID Phase 40: integrated, offline and non-authorizing assessment.

Re-evaluates *raw* evidence through the Phase 37–39 validators instead of
trusting independent reports' self-declared pass flags. Only synthetic data.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from said.evidence_chain import verify_chain
from said.staging_security import assess_staging_security
from said.recovery_drill import assess_drill
from said.observability_gate import assess_observability


class IntegratedEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.integrated-security-input.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    release_chain: dict
    staging_snapshot: dict
    recovery_drill: dict
    observability_snapshot: dict


def assess_integrated(raw: dict, *, now: datetime | None = None) -> dict:
    """Do all four assessments again; no result is allowed to grant deployment."""
    bundle = IntegratedEvidence.model_validate(raw)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Timezone-aware assessment required")
    checks = (
        ("release_chain", verify_chain, bundle.release_chain, "integrity_consistent"),
        ("staging_security", assess_staging_security, bundle.staging_snapshot,
         "declared_controls_complete"),
        ("recovery_drill", assess_drill, bundle.recovery_drill,
         "declared_recovery_checks_passed"),
        ("observability", assess_observability, bundle.observability_snapshot,
         "declared_telemetry_healthy"),
    )
    results = {}
    issues = []
    for name, assessor, evidence, success_field in checks:
        # Invalid or incomplete component inputs must fail closed, not crash
        # the full assessment or allow remaining components to hide a failure.
        try:
            outcome = (assessor(evidence, now=current) if name in
                       ("recovery_drill", "observability") else assessor(evidence))
        except (ValueError, TypeError, KeyError, OverflowError):
            issues.append(name + "_invalid_evidence")
            results[name] = {"passed": False, "issues": ["invalid_evidence"]}
            continue
        passed = outcome.get(success_field) is True
        results[name] = {"passed": passed, "issues": outcome.get("issues", [])}
        if not passed:
            issues.append(name + "_failed")
        if outcome.get("commit_sha") != bundle.commit_sha:
            issues.append(name + "_commit_mismatch")
        if any(outcome.get(flag) is not False for flag in (
                "staging_deploy_authorized", "production_deploy_authorized",
                "telecom_operations_enabled")):
            issues.append(name + "_unexpected_authorization")
    chain_root = (results["release_chain"]["passed"] and
                  bundle.release_chain.get("root_digest"))
    staging_root = bundle.staging_snapshot.get("evidence_chain_root")
    if not isinstance(chain_root, str) or chain_root != staging_root:
        issues.append("staging_release_root_mismatch")
    # Check declared backup/restore time is consistent with monitoring's
    # claimed latest drill, without claiming independent timestamp attestation.
    if results["recovery_drill"]["passed"] and results["observability"]["passed"]:
        try:
            restored = datetime.fromisoformat(
                bundle.recovery_drill["restored_at"].replace("Z", "+00:00"))
            latest = datetime.fromisoformat(
                bundle.observability_snapshot["last_successful_recovery_drill_at"].replace(
                    "Z", "+00:00"))
            if abs((restored - latest).total_seconds()) > 60:
                issues.append("recovery_observability_drill_timestamp_mismatch")
        except (KeyError, AttributeError, ValueError, TypeError):
            issues.append("recovery_observability_drill_timestamp_invalid")

    report = {
        "schema": "said.mock.integrated-security-assessment.v1",
        "commit_sha": bundle.commit_sha,
        "components": results,
        "integrated_checks_passed": not issues,
        "issues": sorted(set(issues)),
        "operator_evidence_independently_authenticated": False,
        "external_release_chain_anchor_verified": False,
        "actual_restore_executed": False,
        "actual_load_test_executed": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    report["sha256"] = hashlib.sha256(json.dumps(
        report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="Offline integrated SAID security assessment")
    parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = assess_integrated(json.loads(args.bundle.read_text(encoding="utf-8")))
    except (ValueError, TypeError, OSError, UnicodeError) as exc:
        print(json.dumps({"integrated_checks_passed": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["integrated_checks_passed"] else 2)


if __name__ == "__main__":
    main()
