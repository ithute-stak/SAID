"""Phase 36: safe staging preparation dossier. No deploy permission.

All supplied evidence must be treated as untrusted until independently
collected and authenticated. This checks consistency, not authenticity.
"""
import argparse
import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class Dossier(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: str = Field(pattern=r"^said[.]mock[.]staging-dossier[.]v1$")
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    ci_report: dict
    pr_review_report: dict
    ruleset_report: dict
    team_report: dict
    audit_host_report: dict


def assess_staging(raw: dict) -> dict:
    """Validate dossier provenance consistency; never approve deployment."""
    dossier = Dossier.model_validate(raw)
    issues = []
    fields = [
        ("ci", dossier.ci_report, "review_candidate"),
        ("pr", dossier.pr_review_report, "github_review_checks_passed"),
        ("rulesets", dossier.ruleset_report, "github_ruleset_checks_passed"),
        ("teams", dossier.team_report, "github_team_membership_checks_passed"),
    ]
    for label, report, flag in fields:
        if report.get("commit_sha") != dossier.commit_sha:
            issues.append(label + "_commit_mismatch")
        if report.get(flag) is not True:
            issues.append(label + "_check_not_passed")
        if report.get("staging_deploy_authorized") is not False or (
            report.get("production_deploy_authorized") is not False
        ):
            issues.append(label + "_invalid_release_authorization")
    host = dossier.audit_host_report
    if host.get("passed") is not True or host.get("host_attested") is not False or (
        host.get("production_approval_granted") is not False
    ):
        issues.append("audit_host_evidence_incomplete_or_untrusted")
    for label, report, flag in fields:
        if report.get("issues"):
            issues.append(label + "_reported_issues")
    if host.get("issues"):
        issues.append("audit_host_reported_issues")
    # A review candidate is NOT staging permission. No real host is attested.
    result = {
        "schema": "said.mock.staging-readiness-report.v1",
        "commit_sha": dossier.commit_sha,
        "dossier_consistent": not issues,
        "issues": sorted(set(issues)),
        "independent_host_attestation_verified": False,
        "independent_review_credentials_verified": False,
        "external_telecom_authorization_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
        "simulated": True,
    }
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["sha256"] = hashlib.sha256(payload).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description="SAID staging dossier consistency (no deploy)")
    parser.add_argument("--dossier", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = assess_staging(json.loads(args.dossier.read_text(encoding="utf-8")))
    except (ValueError, OSError, UnicodeError, TypeError) as exc:
        print(json.dumps({"dossier_consistent": False, "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["dossier_consistent"] else 2)


if __name__ == "__main__":
    main()
