"""Phase 35: no-network ruleset and governance regression tests."""
import pytest
from said.ruleset_bypass_audit import inspect_rulesets, fetch_ruleset_review
from said.verified_release import github_json

SHA = "a" * 40


def fixtures():
    entry = {"id": 7}
    detail = {
        "id": 7, "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [],
        "rules": [
            {"type": "pull_request", "parameters": {"required_approving_review_count": 2}},
            {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "tests"}]}},
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
    }
    return [entry], [detail]


def test_declared_full_ruleset_is_review_only():
    listing, details = fixtures()
    assessment = inspect_rulesets(listing, details)
    assert assessment["passed"]
    assert not assessment["organization_and_enterprise_bypass_exhaustively_verified"]
    assert not assessment["production_deploy_authorized"]
    assert not assessment["reviewer_institutional_authority_verified"]


def test_authenticated_fetch_is_not_production_approval():
    listing, details = fixtures()
    seen = []
    def fetch(path, token):
        seen.append(path)
        assert token == "synthetic-read-only"
        return listing if path.endswith("rulesets?per_page=100") else details[0]
    report = fetch_ruleset_review(SHA, "synthetic-read-only", fetch=fetch)
    assert report["github_ruleset_checks_passed"]
    assert not report["release_authorization_granted"]
    assert not report["org_enterprise_effective_bypass_proven"]
    assert not report["staging_deploy_authorized"]
    assert len(report["sha256"]) == 64
    assert len(seen) == 2


@pytest.mark.parametrize("mutate,issue", [
    (lambda d: d.update(bypass_actors=[{"actor_id": 1, "actor_type": "OrganizationAdmin"}]),
     "ruleset_bypass_actor_present"),
    (lambda d: d.pop("bypass_actors"), "ruleset_bypass_details_missing"),
    (lambda d: d.update(enforcement="disabled"), "active_main_ruleset_missing"),
    (lambda d: d["conditions"]["ref_name"].update(exclude=["refs/heads/main"]),
     "ruleset_main_exclusions_unverified"),
    (lambda d: d["conditions"]["ref_name"].update(include=["refs/heads/feature-*"]),
     "ambiguous_ruleset_branch_conditions"),
    (lambda d: d["rules"].pop(), "missing_rule_deletion"),
    (lambda d: d["rules"][0]["parameters"].update(required_approving_review_count=1),
     "two_approvals_not_required"),
    (lambda d: d["rules"][1]["parameters"].update(required_status_checks=[]),
     "tests_status_check_not_required"),
])
def test_insecure_or_incomplete_rulesets_fail(mutate, issue):
    listing, details = fixtures()
    mutate(details[0])
    outcome = inspect_rulesets(listing, details)
    assert not outcome["passed"]
    assert issue in outcome["issues"]


def test_partial_inventory_and_id_mismatch_denied():
    listing, details = fixtures()
    assert not inspect_rulesets(listing * 100, details)["passed"]
    assert "ruleset_identity_mismatch" in inspect_rulesets(listing, [{"id": 8}])["issues"]
    assert "ruleset_detail_inventory_incomplete" in inspect_rulesets(listing, [])["issues"]


def test_missing_token_and_bad_sha_rejected():
    with pytest.raises(ValueError):
        fetch_ruleset_review(SHA, "")
    with pytest.raises(ValueError):
        fetch_ruleset_review("short", "synthetic")


def test_github_api_allowlist_prevents_arbitrary_ruleset_ids():
    with pytest.raises(ValueError):
        github_json("/repos/other/SAID/rulesets?per_page=100", "test")
    with pytest.raises(ValueError):
        github_json("/repos/ithute-stak/SAID/rulesets/7/../../issues", "test")
    with pytest.raises(ValueError):
        github_json("/repos/ithute-stak/SAID/rulesets?per_page=1000", "test")
