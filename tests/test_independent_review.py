"""Phase 33: release signoffs must remain separated and non-authorizing."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from said.independent_review import assess_package, assess_rulesets


def package():
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema": "said.mock.release-review.v1",
        "commit_sha": "a" * 40, "run_id": 456789,
        "verified_ci_report_sha256": "b" * 64,
        "verified_ci_review_candidate": True,
        "original_author_subject": "code-author",
        "deployer_subject": "deployment-owner",
        "signoffs": [
            {"role": "security_reviewer", "subject_reference": "external-security",
             "decision": "approve", "evidence_reference": "security/review/456",
             "recorded_at": now},
            {"role": "operations_reviewer", "subject_reference": "operations-review",
             "decision": "approve", "evidence_reference": "operations/review/456",
             "recorded_at": now},
        ],
        "ruleset_assessment": {"schema": "said.mock.rulesets.v1",
                               "complete": True, "rulesets": [{
                                   "target": "branch", "enforcement": "active",
                                   "applies_to_main": True, "bypass_actors": [],
                                   "rules": [{"type": x} for x in (
                                       "pull_request", "required_status_checks",
                                       "non_fast_forward", "deletion")],
                               }]},
    }


def test_declared_complete_still_cannot_authorize_deployment():
    report = assess_package(package())
    assert report["review_candidate"]
    assert report["declared_review_complete"]
    assert not report["staging_deploy_authorized"]
    assert not report["production_deploy_authorized"]
    assert not report["approval_evidence_authenticated"]
    assert not report["ruleset_data_independently_verified"]
    assert len(report["report_sha256"]) == 64
    assert report == assess_package(package())


@pytest.mark.parametrize("subject", ["code-author", "deployment-owner"])
def test_author_and_deployer_cannot_signoff(subject):
    raw = package()
    raw["signoffs"][0]["subject_reference"] = subject
    assert "reviewer_or_deployer_independence_failed" in assess_package(raw)["issues"]


def test_two_reviewers_cannot_be_same_person():
    raw = package()
    raw["signoffs"][1]["subject_reference"] = raw["signoffs"][0]["subject_reference"]
    assert not assess_package(raw)["review_candidate"]


def test_missing_and_rejected_reviews():
    raw = package()
    raw["signoffs"][1]["decision"] = "pending"
    assert "unapproved_operations_reviewer" in assess_package(raw)["issues"]
    raw = package()
    raw["signoffs"][0]["role"] = "operations_reviewer"
    with pytest.raises(ValidationError):
        assess_package(raw)
    raw = package()
    raw["signoffs"].pop()
    with pytest.raises(ValidationError):
        assess_package(raw)


def test_signoff_timestamp_freshness():
    raw = package()
    raw["signoffs"][0]["recorded_at"] = (
        datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    assert not assess_package(raw)["review_candidate"]
    raw["signoffs"][0]["recorded_at"] = (
        datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert not assess_package(raw)["review_candidate"]
    raw["signoffs"][0]["recorded_at"] = "2026-11-04T10:00:00"
    assert not assess_package(raw)["review_candidate"]


def test_report_denies_unverified_ci_claim():
    raw = package()
    raw["verified_ci_review_candidate"] = False
    assert "verified_ci_review_candidate_missing" in assess_package(raw)["issues"]


@pytest.mark.parametrize("modification, issue", [
    (lambda r: r.update(complete=False), "ruleset_inventory_not_complete"),
    (lambda r: r["rulesets"][0].update(enforcement="disabled"), "active_main_ruleset_missing"),
    (lambda r: r["rulesets"][0].update(bypass_actors=[{"actor_id": 1}]), "unreviewed_ruleset_bypass"),
    (lambda r: r["rulesets"][0]["rules"].pop(), "branch_deletion_prevention_rule_missing"),
])
def test_ruleset_fail_closed(modification, issue):
    raw = package()["ruleset_assessment"]
    modification(raw)
    assert issue in assess_rulesets(raw)["issues"]
    assert not assess_rulesets(raw)["passed"]


def test_invalid_schema_and_extra_fields_are_rejected():
    raw = package()
    raw["schema"] = "said.mock.other.v1"
    with pytest.raises(ValidationError):
        assess_package(raw)
    raw = package()
    raw["actual_deployment_approval"] = True
    with pytest.raises(ValidationError):
        assess_package(raw)
