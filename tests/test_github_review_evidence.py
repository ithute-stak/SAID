"""Mock GitHub endpoint responses; no network, tokens, or live approvals."""
from datetime import datetime, timedelta, timezone

import pytest

from said.github_review_evidence import (
    fetch_evidence, verify_effective_rules, verify_pr_reviews, REQUIRED_RULE_TYPES,
)
from said.verified_release import github_json

SHA = "a" * 40
PR = 456


def fixtures():
    now = datetime.now(timezone.utc).isoformat()
    pr = {"number": PR, "state": "open", "draft": False,
          "head": {"sha": SHA, "repo": {"full_name": "ithute-stak/SAID"}},
          "base": {"ref": "main", "repo": {"full_name": "ithute-stak/SAID"}},
          "user": {"login": "codeauthor"}}
    reviews = [
        {"id": 10, "user": {"login": "securityperson"}, "state": "APPROVED",
         "commit_id": SHA, "submitted_at": now},
        {"id": 11, "user": {"login": "operationsperson"}, "state": "APPROVED",
         "commit_id": SHA, "submitted_at": now},
    ]
    rules = [{"type": name, "parameters": {}} for name in sorted(REQUIRED_RULE_TYPES)]
    return pr, reviews, rules


def review(pr, entries):
    return verify_pr_reviews(
        pr, entries, commit_sha=SHA, pr_number=PR,
        security_login="securityperson",
        operations_login="operationsperson",
        deployer_login="deploymentperson")


def test_green_review_is_not_authorization():
    pr, reviews, rules = fixtures()
    result = review(pr, reviews)
    assert result["passed"]
    assert result["security_role_membership_verified"] is False
    assert result["production_deploy_authorized"] is False
    assert verify_effective_rules(rules)["passed"] is True


def test_full_authenticated_fetch_still_refuses_release_approval():
    pr, reviews, rules = fixtures()
    def fake_fetch(path, token):
        assert token == "fake-read-token"
        assert path.startswith("/repos/ithute-stak/SAID/")
        if path.endswith("/reviews?per_page=100"):
            return reviews
        if path.endswith("/rules/branches/main?per_page=100"):
            return rules
        if path.endswith(f"/pulls/{PR}"):
            return pr
        raise AssertionError(path)
    report = fetch_evidence(
        SHA, PR, "fake-read-token",
        security_login="securityperson",
        operations_login="operationsperson",
        deployer_login="deploymentperson",
        fetch=fake_fetch)
    assert report["github_review_checks_passed"]
    assert report["github_effective_rule_checks_passed"]
    assert not report["release_approval_granted"]
    assert not report["ruleset_bypass_actors_verified"]
    assert not report["staging_deploy_authorized"]
    assert len(report["report_sha256"]) == 64


@pytest.mark.parametrize("mutator,expected", [
    (lambda p,r: p["head"].update(sha="b"*40), "pull_request_commit_mismatch"),
    (lambda p,r: p["base"].update(ref="evil"), "wrong_base_repository_or_branch"),
    (lambda p,r: p["head"]["repo"].update(full_name="untrusted/SAID"), "untrusted_head_repository"),
    (lambda p,r: p.update(draft=True), "pr_not_open_for_review"),
    (lambda p,r: r[0].update(commit_id="b"*40), "security_approval_wrong_commit"),
    (lambda p,r: r[0].update(state="CHANGES_REQUESTED"), "security_approval_not_current"),
    (lambda p,r: r[0].update(submitted_at=(datetime.now(timezone.utc)-timedelta(days=8)).isoformat()), "security_approval_not_fresh"),
    (lambda p,r: r[0].update(submitted_at="2026-11-04T12:00:00"), "security_approval_not_fresh"),
    (lambda p,r: r.pop(), "operations_approval_missing"),
])
def test_bad_review_metadata_denies(mutator, expected):
    pr, reviews, _ = fixtures()
    mutator(pr, reviews)
    assert expected in review(pr, reviews)["issues"]


def test_newer_rejection_invalidates_prior_approval():
    pr, reviews, _ = fixtures()
    reviews.append({"id": 99, "user": {"login": "securityperson"},
                    "state": "CHANGES_REQUESTED", "commit_id": SHA,
                    "submitted_at": datetime.now(timezone.utc).isoformat()})
    assert "security_approval_not_current" in review(pr, reviews)["issues"]


def test_self_approval_and_cross_role_collision():
    pr, reviews, _ = fixtures()
    bad = verify_pr_reviews(
        pr, reviews, commit_sha=SHA, pr_number=PR,
        security_login="codeauthor", operations_login="operationsperson",
        deployer_login="deploymentperson")
    assert "author_reviewers_deployer_not_independent" in bad["issues"]


def test_rules_missing_and_truncated():
    _, _, rules = fixtures()
    assert not verify_effective_rules(rules[:-1])["passed"]
    assert "rules_response_missing_or_incomplete" in verify_effective_rules(rules * 25)["issues"]


def test_review_pagination_does_not_silently_pass():
    pr, reviews, rules = fixtures()
    def fake(path, token):
        return reviews * 50 if "/reviews?" in path else (rules if "/rules/" in path else pr)
    result = fetch_evidence(
        SHA, PR, "fake-read-token",
        security_login="securityperson", operations_login="operationsperson",
        deployer_login="deploymentperson", fetch=fake)
    assert not result["github_review_checks_passed"]


def test_missing_token_rejected_before_network():
    with pytest.raises(ValueError):
        fetch_evidence(SHA, PR, "", security_login="securityperson",
                       operations_login="operationsperson", deployer_login="deploymentperson")


def test_allowlist_rejects_wrong_repository_and_unsafe_path():
    with pytest.raises(ValueError):
        github_json("/repos/attacker/SAID/pulls/456/reviews?per_page=100", "test")
    with pytest.raises(ValueError):
        github_json("/repos/ithute-stak/SAID/pulls/456/reviews?per_page=999", "test")
