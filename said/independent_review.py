"""Phase 33: read-only independent release review and ruleset policy assessment.

This module accepts operator-supplied evidence; no approvals, keys, or
deployment are performed. Never substitute self-reported evidence for
GitHub-authenticated review, independent security review or law.
"""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Signoff(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    role: Literal["security_reviewer", "operations_reviewer"]
    subject_reference: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9_.-]+$")
    decision: Literal["approve", "reject", "pending"]
    evidence_reference: str = Field(min_length=6, max_length=200,
                                    pattern=r"^[A-Za-z0-9_./:#-]+$")
    recorded_at: datetime


class ReviewPackage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema: Literal["said.mock.release-review.v1"]
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    run_id: int = Field(gt=0)
    verified_ci_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verified_ci_review_candidate: bool
    original_author_subject: str = Field(min_length=3, max_length=120)
    deployer_subject: str = Field(min_length=3, max_length=120)
    signoffs: list[Signoff] = Field(min_length=2, max_length=2)
    ruleset_assessment: dict

    @model_validator(mode="after")
    def two_distinct_roles(self):
        if {s.role for s in self.signoffs} != {"security_reviewer", "operations_reviewer"}:
            raise ValueError("Both distinct review roles are required")
        return self


def assess_rulesets(raw: dict) -> dict:
    """Conservative rule assessment of a supplied, *complete* GitHub ruleset response.

    A missing/partial response always fails. A passing assessment does not
    independently authenticate returned objects, bypass actors, or rulesets.
    """
    issues = []
    if not isinstance(raw, dict):
        raise ValueError("Ruleset assessment expects an object")
    if raw.get("schema") != "said.mock.rulesets.v1" or raw.get("complete") is not True:
        issues.append("ruleset_inventory_not_complete")
    rulesets = raw.get("rulesets")
    if not isinstance(rulesets, list) or not rulesets:
        rulesets = []
        issues.append("rulesets_missing")
    applicable = [
        r for r in rulesets if isinstance(r, dict) and
        r.get("enforcement") == "active" and
        r.get("target") == "branch" and
        r.get("applies_to_main") is True
    ]
    if not applicable:
        issues.append("active_main_ruleset_missing")
    for r in applicable:
        if r.get("bypass_actors"):
            issues.append("unreviewed_ruleset_bypass")
        definitions = r.get("rules")
        if not isinstance(definitions, list):
            issues.append("ruleset_rules_missing")
            continue
        types = {x.get("type") for x in definitions if isinstance(x, dict)}
        if "pull_request" not in types:
            issues.append("pr_review_rule_missing")
        if "required_status_checks" not in types:
            issues.append("ci_status_rule_missing")
        if "non_fast_forward" not in types:
            issues.append("force_push_prevention_rule_missing")
        if "deletion" not in types:
            issues.append("branch_deletion_prevention_rule_missing")
    return {
        "passed": not issues,
        "issues": sorted(set(issues)),
        "operator_supplied": True,
        "github_ruleset_api_verified": False,
        "effective_rule_precedence_verified": False,
        "staging_deploy_authorized": False,
    }


def assess_package(raw: dict, *, now: datetime | None = None) -> dict:
    """Check declared review separation and freshness, but never issue approval."""
    package = ReviewPackage.model_validate(raw)
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Assessment time needs timezone")
    issues = []
    if not package.verified_ci_review_candidate:
        issues.append("verified_ci_review_candidate_missing")
    reviewers = [s.subject_reference for s in package.signoffs]
    if len(set(reviewers)) != 2 or package.original_author_subject in reviewers or (
        package.deployer_subject in reviewers
    ) or package.deployer_subject == package.original_author_subject:
        issues.append("reviewer_or_deployer_independence_failed")
    for s in package.signoffs:
        if s.decision != "approve":
            issues.append("unapproved_" + s.role)
        if s.recorded_at.tzinfo is None or not 0 <= (
            current - s.recorded_at
        ).total_seconds() <= 7 * 86400:
            issues.append("stale_or_future_" + s.role)
    policy = assess_rulesets(package.ruleset_assessment)
    if not policy["passed"]:
        issues.extend(policy["issues"])
    report = {
        "schema": "said.mock.release-review-assessment.v1",
        "commit_sha": package.commit_sha,
        "run_id": package.run_id,
        "declared_review_complete": not issues,
        "issues": sorted(set(issues)),
        "approval_evidence_authenticated": False,
        "ruleset_data_independently_verified": False,
        "verified_ci_report_link_authenticated": False,
        "review_candidate": not issues,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
        "simulated": True,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="SAID offline independent release review check")
    parser.add_argument("--review-package", type=Path, required=True)
    args = parser.parse_args()
    try:
        value = json.loads(args.review_package.read_text(encoding="utf-8"))
        result = assess_package(value)
    except (OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"review_candidate": False, "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["review_candidate"] else 2)


if __name__ == "__main__":
    main()
