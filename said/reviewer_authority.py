"""Phase 36: read-only GitHub reviewer team authority checks.

GitHub team membership is evidence of *GitHub organization permissions*
only, NOT external institutional authorization. No deploy or signing.
"""
import argparse
import hashlib
import json
import os
import re

from said.verified_release import REPO, SHA, github_json

ORG = "ithute-stak"
TEAM_SLUGS = ("said-security-reviewers", "said-operations-reviewers")
LOGIN = re.compile(r"^[A-Za-z0-9-]{1,39}$")


def verify_memberships(reviews: dict, security: dict, operations: dict,
                       *, commit_sha: str, security_login: str,
                       operations_login: str, author_login: str,
                       deployer_login: str) -> dict:
    """Check exact provenance of prerequisite review report and team membership."""
    if not SHA.fullmatch(commit_sha):
        raise ValueError("Expected exact 40-character commit SHA")
    if not isinstance(reviews, dict) or not isinstance(security, dict) or not isinstance(operations, dict):
        raise ValueError("Incomplete reviewer evidence")
    identities = [security_login, operations_login, author_login, deployer_login]
    issues = []
    if any(not isinstance(login, str) or not LOGIN.fullmatch(login) for login in identities):
        issues.append("invalid_identity")
    elif len(set(login.lower() for login in identities)) != 4:
        issues.append("reviewer_author_deployer_overlap")
    if reviews.get("commit_sha") != commit_sha or reviews.get("github_review_checks_passed") is not True:
        issues.append("github_review_evidence_not_verified")
    if reviews.get("staging_deploy_authorized") is not False or reviews.get("production_deploy_authorized") is not False:
        issues.append("unexpected_release_authorization_claim")
    for role, item in (("security", security), ("operations", operations)):
        if item.get("state") != "active":
            issues.append(role + "_team_membership_inactive")
        if item.get("role") not in ("member", "maintainer"):
            issues.append(role + "_team_role_invalid")
    return {
        "schema": "said.mock.github-team-reviewer-check.v1",
        "commit_sha": commit_sha,
        "github_team_membership_checks_passed": not issues,
        "issues": sorted(set(issues)),
        "github_team_membership_not_institutional_authorization": True,
        "independent_security_credential_verified": False,
        "external_organization_governance_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }


def fetch_reviewer_authority(commit_sha: str, *, security_login: str,
                             operations_login: str, author_login: str,
                             deployer_login: str, pr_review_report: dict,
                             token: str, fetch=github_json) -> dict:
    """Fetch fixed-organization team memberships using read-only GitHub REST."""
    if not token or not SHA.fullmatch(commit_sha):
        raise ValueError("Read-only token and valid commit required")
    if any(not isinstance(login, str) or not LOGIN.fullmatch(login) for login in
           (security_login, operations_login, author_login, deployer_login)):
        raise ValueError("Invalid GitHub login")
    security = fetch(f"/orgs/{ORG}/teams/{TEAM_SLUGS[0]}/memberships/{security_login}", token)
    operations = fetch(f"/orgs/{ORG}/teams/{TEAM_SLUGS[1]}/memberships/{operations_login}", token)
    result = verify_memberships(pr_review_report, security, operations,
        commit_sha=commit_sha, security_login=security_login,
        operations_login=operations_login, author_login=author_login,
        deployer_login=deployer_login)
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["sha256"] = hashlib.sha256(canonical).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description="Read-only GitHub reviewer team check")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--security-login", required=True)
    parser.add_argument("--operations-login", required=True)
    parser.add_argument("--author-login", required=True)
    parser.add_argument("--deployer-login", required=True)
    parser.add_argument("--pr-review-evidence", required=True)
    args = parser.parse_args()
    try:
        with open(args.pr_review_evidence, encoding="utf-8") as file:
            raw = json.load(file)
        report = fetch_reviewer_authority(args.commit,
            security_login=args.security_login,
            operations_login=args.operations_login,
            author_login=args.author_login,
            deployer_login=args.deployer_login,
            pr_review_report=raw, token=os.environ.get("SAID_GITHUB_READ_TOKEN", ""))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"github_team_membership_checks_passed": False,
                          "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report["github_team_membership_checks_passed"] else 2)


if __name__ == "__main__":
    main()
