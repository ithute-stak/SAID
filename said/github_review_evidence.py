"""Phase 34: authenticated, read-only GitHub PR review and effective rule evidence.

GitHub verifies account logins and review data, NOT institutional security
roles or regulator authorization. Never deploys or signs evidence.
"""
import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timezone

from said.verified_release import REPO, SHA, github_json

REQUIRED_RULE_TYPES = frozenset({
    "pull_request", "required_status_checks", "non_fast_forward", "deletion"
})


def _iso(value):
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt if dt.tzinfo is not None else None
    except ValueError:
        return None


def verify_pr_reviews(pr: dict, reviews: list, *, commit_sha: str,
                      pr_number: int, security_login: str,
                      operations_login: str, deployer_login: str,
                      now: datetime | None = None) -> dict:
    """Fail closed if named GitHub reviewers lack fresh head-commit approvals."""
    if not SHA.fullmatch(commit_sha) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("Invalid PR identity")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("Timezone-aware assessment required")
    issues = []
    if not isinstance(pr, dict) or not isinstance(reviews, list):
        raise ValueError("Invalid GitHub review response")
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    author = (pr.get("user") or {}).get("login")
    if pr.get("number") != pr_number or head.get("sha") != commit_sha:
        issues.append("pull_request_commit_mismatch")
    if base.get("ref") != "main" or (base.get("repo") or {}).get("full_name") != REPO:
        issues.append("wrong_base_repository_or_branch")
    if (head.get("repo") or {}).get("full_name") != REPO:
        issues.append("untrusted_head_repository")
    identities = [author, security_login, operations_login, deployer_login]
    if any(not isinstance(x, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", x)
           for x in identities) or len(set(x.lower() for x in identities)) != 4:
        issues.append("author_reviewers_deployer_not_independent")
    latest = {}
    for entry in reviews:
        if not isinstance(entry, dict):
            issues.append("malformed_review_entry")
            continue
        login = (entry.get("user") or {}).get("login")
        timestamp = _iso(entry.get("submitted_at"))
        if not isinstance(login, str) or timestamp is None:
            issues.append("incomplete_review_metadata")
            continue
        key = login.lower()
        # REST review IDs are monotonically increasing for later review events;
        # fail if IDs cannot be compared or duplicate review IDs are present.
        ident = entry.get("id")
        if isinstance(ident, bool) or not isinstance(ident, int) or ident <= 0:
            issues.append("invalid_review_id")
            continue
        if key not in latest or ident > latest[key]["id"]:
            latest[key] = entry
    for role, login in [("security", security_login), ("operations", operations_login)]:
        review = latest.get(login.lower())
        if review is None:
            issues.append(role + "_approval_missing")
            continue
        submitted = _iso(review.get("submitted_at"))
        if review.get("state") != "APPROVED":
            issues.append(role + "_approval_not_current")
        if review.get("commit_id") != commit_sha:
            issues.append(role + "_approval_wrong_commit")
        if submitted is None or not 0 <= (current - submitted).total_seconds() <= 7 * 86400:
            issues.append(role + "_approval_not_fresh")
    if (pr.get("draft") is not False or pr.get("state") != "open"):
        issues.append("pr_not_open_for_review")
    return {
        "passed": not issues, "issues": sorted(set(issues)),
        "github_review_metadata_checked": True,
        "security_role_membership_verified": False,
        "operations_role_membership_verified": False,
        "account_identity_independently_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
    }


def verify_effective_rules(raw: list) -> dict:
    """Examine GitHub's effective main-branch rules without guessing bypass."""
    if not isinstance(raw, list) or len(raw) >= 100:
        return {"passed": False, "issues": ["rules_response_missing_or_incomplete"],
                "bypass_permissions_verified": False}
    found = set()
    for entry in raw:
        if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
            return {"passed": False, "issues": ["malformed_effective_rule"],
                    "bypass_permissions_verified": False}
        found.add(entry["type"])
    missing = sorted(REQUIRED_RULE_TYPES - found)
    return {
        "passed": not missing, "issues": ["missing_rule_" + x for x in missing],
        "effective_rules_fetched_from_github": True,
        "bypass_permissions_verified": False,
        "staging_deploy_authorized": False,
    }


def fetch_evidence(commit_sha: str, pr_number: int, token: str, *,
                   security_login: str, operations_login: str,
                   deployer_login: str, fetch=github_json) -> dict:
    """Fetch fixed GitHub API paths; fail closed on pagination and API errors."""
    if not token or not SHA.fullmatch(commit_sha) or isinstance(pr_number, bool) or pr_number <= 0:
        raise ValueError("Missing token or invalid commit/PR")
    root = "/repos/" + REPO
    pr = fetch(root + f"/pulls/{pr_number}", token)
    reviews = fetch(root + f"/pulls/{pr_number}/reviews?per_page=100", token)
    rules = fetch(root + "/rules/branches/main?per_page=100", token)
    if not isinstance(reviews, list) or len(reviews) >= 100:
        review = {"passed": False, "issues": ["review_response_missing_or_incomplete"],
                  "security_role_membership_verified": False,
                  "operations_role_membership_verified": False}
    else:
        review = verify_pr_reviews(
            pr, reviews, commit_sha=commit_sha, pr_number=pr_number,
            security_login=security_login, operations_login=operations_login,
            deployer_login=deployer_login)
    effective = verify_effective_rules(rules)
    report = {
        "schema": "said.mock.github-independent-review.v1",
        "commit_sha": commit_sha,
        "pull_request_number": pr_number,
        "github_review_checks_passed": review["passed"],
        "github_effective_rule_checks_passed": effective["passed"],
        "issues": sorted(set(review["issues"] + effective["issues"])),
        "github_api_metadata_checked": True,
        "reviewer_institutional_roles_verified": False,
        "ruleset_bypass_actors_verified": False,
        "independent_security_signoff_verified": False,
        "release_approval_granted": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return report


def main():
    parser = argparse.ArgumentParser(description="SAID read-only GitHub review evidence")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--security-login", required=True)
    parser.add_argument("--operations-login", required=True)
    parser.add_argument("--deployer-login", required=True)
    args = parser.parse_args()
    token = os.getenv("SAID_GITHUB_READ_TOKEN", "")
    try:
        report = fetch_evidence(args.commit, args.pr, token,
                                security_login=args.security_login,
                                operations_login=args.operations_login,
                                deployer_login=args.deployer_login)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"github_review_checks_passed": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["github_review_checks_passed"] and
                     report["github_effective_rule_checks_passed"] else 2)


if __name__ == "__main__":
    main()
