"""Phase 35: read-only GitHub ruleset bypass assessment, review candidate only.

Conservative: incomplete rulesets, bypass allowances, ambiguous branches,
missing approval governance, and pagination fail. Institutional role
authorization must be assessed independently; no deployment operation.
"""
import argparse
import hashlib
import json
import os
import re

from said.verified_release import REPO, SHA, github_json

RULE_TYPES = frozenset({"pull_request", "required_status_checks",
                        "non_fast_forward", "deletion"})


def inspect_rulesets(listing: list, details: list) -> dict:
    """Require complete, active, strictly main-scoped ruleset with no bypass.

    The detail is fetched by the caller using a fixed allowlist; list-only
    records are insufficient evidence for complete bypass restrictions.
    """
    issues = []
    if not isinstance(listing, list) or len(listing) >= 100:
        issues.append("ruleset_inventory_incomplete")
        listing = []
    if not isinstance(details, list) or len(details) != len(listing):
        issues.append("ruleset_detail_inventory_incomplete")
        details = []
    listed_ids = set()
    for item in listing:
        if not isinstance(item, dict) or type(item.get("id")) is not int or item["id"] <= 0:
            issues.append("malformed_ruleset_listing")
            continue
        listed_ids.add(item["id"])
    by_id = {}
    for item in details:
        if not isinstance(item, dict) or type(item.get("id")) is not int:
            issues.append("malformed_ruleset_detail")
            continue
        if item["id"] in by_id:
            issues.append("duplicate_ruleset_detail")
        by_id[item["id"]] = item
    if set(by_id) != listed_ids:
        issues.append("ruleset_identity_mismatch")
    applicable = []
    for item in details:
        if not isinstance(item, dict):
            continue
        if item.get("target") != "branch" or item.get("enforcement") != "active":
            continue
        condition = item.get("conditions") or {}
        ref_name = condition.get("ref_name") or {}
        includes = ref_name.get("include")
        excludes = ref_name.get("exclude")
        if not isinstance(includes, list) or not isinstance(excludes, list):
            issues.append("ambiguous_ruleset_branch_conditions")
            continue
        # Only explicit main ref is recognized. Wildcard patterns and negative
        # patterns may have wider semantics; never infer complete coverage.
        if "~DEFAULT_BRANCH" in includes or "refs/heads/main" in includes:
            if excludes:
                issues.append("ruleset_main_exclusions_unverified")
                continue
            applicable.append(item)
        elif any(isinstance(v, str) and ("*" in v or "~" in v)
                 for v in includes):
            issues.append("ambiguous_ruleset_branch_conditions")
    if not applicable:
        issues.append("active_main_ruleset_missing")
    allowed = set()
    for item in applicable:
        if item.get("bypass_actors") is None:
            issues.append("ruleset_bypass_details_missing")
        elif item.get("bypass_actors") != []:
            issues.append("ruleset_bypass_actor_present")
        rules = item.get("rules")
        if not isinstance(rules, list):
            issues.append("ruleset_rule_definitions_missing")
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                issues.append("malformed_ruleset_rule")
                continue
            kind = rule.get("type")
            if kind == "pull_request":
                params = rule.get("parameters") or {}
                if type(params.get("required_approving_review_count")) is not int or (
                    params["required_approving_review_count"] < 2
                ):
                    issues.append("two_approvals_not_required")
            if kind == "required_status_checks":
                params = rule.get("parameters") or {}
                checks = params.get("required_status_checks")
                if not isinstance(checks, list) or not any(
                    isinstance(c, dict) and c.get("context") == "tests" for c in checks
                ):
                    issues.append("tests_status_check_not_required")
            if isinstance(kind, str):
                allowed.add(kind)
    for missing in RULE_TYPES - allowed:
        issues.append("missing_rule_" + missing)
    return {
        "passed": not issues,
        "issues": sorted(set(issues)),
        "ruleset_details_from_github_expected": True,
        "organization_and_enterprise_bypass_exhaustively_verified": False,
        "reviewer_institutional_authority_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
    }


def fetch_ruleset_review(commit_sha: str, token: str, *, fetch=github_json) -> dict:
    """Read only exact repository rulesets, with bounded full detail for each."""
    if not SHA.fullmatch(commit_sha) or not token:
        raise ValueError("Exact commit SHA and read-only token required")
    root = "/repos/" + REPO
    listing = fetch(root + "/rulesets?per_page=100", token)
    if not isinstance(listing, list) or len(listing) >= 100:
        assessment = inspect_rulesets(listing, [])
    else:
        details = []
        for entry in listing:
            if not isinstance(entry, dict) or type(entry.get("id")) is not int or entry["id"] <= 0:
                raise ValueError("Malformed ruleset identifier")
            details.append(fetch(root + "/rulesets/" + str(entry["id"]), token))
        assessment = inspect_rulesets(listing, details)
    report = {
        "schema": "said.mock.ruleset-bypass-assessment.v1",
        "commit_sha": commit_sha,
        "repo": REPO,
        "github_ruleset_checks_passed": assessment["passed"],
        "issues": assessment["issues"],
        "github_data_authenticated_via_tls": True,
        "org_enterprise_effective_bypass_proven": False,
        "independent_organization_reviewer_roles_proven": False,
        "release_authorization_granted": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="Read-only SAID ruleset bypass audit")
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        result = fetch_ruleset_review(args.commit, os.getenv("SAID_GITHUB_READ_TOKEN", ""))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"github_ruleset_checks_passed": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["github_ruleset_checks_passed"] else 2)


if __name__ == "__main__":
    main()
