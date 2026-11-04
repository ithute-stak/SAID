"""Offline Phase 36 governance tests. Never access a live GitHub organization."""
import copy

import pytest

from said.reviewer_authority import verify_memberships, fetch_reviewer_authority
from said.staging_dossier import assess_staging
from said.verified_release import github_json

SHA = "a" * 40
SECURITY = "security-person"
OPERATIONS = "operations-person"
AUTHOR = "author-person"
DEPLOYER = "deployer-person"


def reviewer():
    return {"commit_sha": SHA, "github_review_checks_passed": True,
            "staging_deploy_authorized": False, "production_deploy_authorized": False}


def memberships():
    return {"state": "active", "role": "member"}, {"state": "active", "role": "maintainer"}


def verify(report=None, security=None, operations=None, **overrides):
    s, o = memberships()
    params = dict(commit_sha=SHA, security_login=SECURITY, operations_login=OPERATIONS,
                  author_login=AUTHOR, deployer_login=DEPLOYER)
    params.update(overrides)
    return verify_memberships(report if report is not None else reviewer(),
                              security if security is not None else s,
                              operations if operations is not None else o, **params)


def dossier():
    security, operations = memberships()
    teams = verify(reviewer(), security, operations)
    return {"schema": "said.mock.staging-dossier.v1", "commit_sha": SHA,
            "ci_report": {"commit_sha": SHA, "review_candidate": True, "issues": [],
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False},
            "pr_review_report": {"commit_sha": SHA, "github_review_checks_passed": True,
                                 "issues": [], "staging_deploy_authorized": False,
                                 "production_deploy_authorized": False},
            "ruleset_report": {"commit_sha": SHA, "github_ruleset_checks_passed": True,
                               "issues": [], "staging_deploy_authorized": False,
                               "production_deploy_authorized": False},
            "team_report": {**teams, "issues": [],
                            "staging_deploy_authorized": False,
                            "production_deploy_authorized": False},
            "audit_host_report": {"passed": True, "host_attested": False,
                                  "production_approval_granted": False, "issues": []}}


def test_active_github_teams_do_not_prove_external_credentials():
    result = verify()
    assert result["github_team_membership_checks_passed"]
    assert result["independent_security_credential_verified"] is False
    assert result["staging_deploy_authorized"] is False
    assert result["production_deploy_authorized"] is False


def test_fixed_org_membership_fetch_still_cannot_approve():
    seen = []
    def fetch(path, token):
        seen.append(path)
        assert token == "synthetic"
        if "said-security-reviewers" in path:
            return {"state": "active", "role": "member"}
        if "said-operations-reviewers" in path:
            return {"state": "active", "role": "member"}
        raise AssertionError(path)
    result = fetch_reviewer_authority(
        SHA, security_login=SECURITY, operations_login=OPERATIONS,
        author_login=AUTHOR, deployer_login=DEPLOYER,
        pr_review_report=reviewer(), token="synthetic", fetch=fetch)
    assert result["github_team_membership_checks_passed"]
    assert len(seen) == 2
    assert len(result["sha256"]) == 64
    assert not result["staging_deploy_authorized"]


@pytest.mark.parametrize("params,issue", [
    ({"security_login": AUTHOR}, "reviewer_author_deployer_overlap"),
    ({"operations_login": SECURITY}, "reviewer_author_deployer_overlap"),
    ({"deployer_login": AUTHOR}, "reviewer_author_deployer_overlap"),
])
def test_identical_review_and_author_accounts_fail(params, issue):
    assert issue in verify(**params)["issues"]


def test_missing_or_inactive_org_team_membership_fails():
    result = verify(security={"state": "pending", "role": "member"})
    assert "security_team_membership_inactive" in result["issues"]
    result = verify(operations={"state": "active", "role": "owner"})
    assert "operations_team_role_invalid" in result["issues"]
    result = verify(report={**reviewer(), "commit_sha": "b" * 40})
    assert "github_review_evidence_not_verified" in result["issues"]


def test_token_required_and_allowlist_protects_membership_requests():
    with pytest.raises(ValueError):
        fetch_reviewer_authority(
            SHA, security_login=SECURITY, operations_login=OPERATIONS,
            author_login=AUTHOR, deployer_login=DEPLOYER,
            pr_review_report=reviewer(), token="")
    with pytest.raises(ValueError):
        github_json("/orgs/other/teams/said-security-reviewers/memberships/person", "token")
    with pytest.raises(ValueError):
        github_json("/orgs/ithute-stak/teams/admins/memberships/person", "token")


def test_consistent_dossier_never_grants_deployment():
    result = assess_staging(dossier())
    assert result["dossier_consistent"]
    assert not result["staging_deploy_authorized"]
    assert not result["production_deploy_authorized"]
    assert not result["independent_host_attestation_verified"]
    assert len(result["sha256"]) == 64


@pytest.mark.parametrize("label", ["ci_report", "pr_review_report",
                                      "ruleset_report", "team_report"])
def test_dossier_fails_on_wrong_commit_or_invalid_release_flags(label):
    data = dossier()
    data[label]["commit_sha"] = "b" * 40
    assert not assess_staging(data)["dossier_consistent"]
    data = dossier()
    data[label]["staging_deploy_authorized"] = True
    assert not assess_staging(data)["dossier_consistent"]


def test_dossier_fails_on_missing_host_or_false_test_evidence():
    data = dossier()
    data["audit_host_report"]["passed"] = False
    assert not assess_staging(data)["dossier_consistent"]
    data = dossier()
    data["ci_report"]["review_candidate"] = False
    assert not assess_staging(data)["dossier_consistent"]


def test_unknown_fields_rejected():
    data = dossier()
    data["production_authorized"] = True
    with pytest.raises(ValueError):
        assess_staging(data)
