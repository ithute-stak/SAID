"""Phase 30 release policy and deployment-approval boundary tests."""
import copy
from pathlib import Path

import pytest
from pydantic import ValidationError

from said.release_gate import REQUIRED, assess_release, inspect_workflow

CI = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


def evidence():
    return {
        "schema": "said.mock.release-evidence.v1",
        "commit_sha": "a" * 40,
        "ci_run_reference": "https://github.com/ithute-stak/SAID/actions/runs/123456",
        "checks": [{"key": key, "status": "success",
                    "evidence_reference": f"ci/run/123456/{key}"} for key in REQUIRED],
        "signer_is_separate_from_application": True,
        "immutable_backup_independently_verified": True,
        "key_custody_independently_verified": True,
        "external_authorization_granted": True,
    }


def test_workflow_policy_has_all_required_checks():
    policy = inspect_workflow(CI.read_text())
    assert policy["passed"]
    assert policy["run_executed"] is False
    changed = CI.read_text().replace(
        "Verify PostgreSQL row-level security with restricted database role",
        "RLS step removed")
    assert "Verify PostgreSQL row-level security with restricted database role" in (
        inspect_workflow(changed)["missing"]
    )


def test_all_reported_evidence_is_only_a_review_candidate():
    report = assess_release(evidence())
    assert report["review_candidate"]
    assert report["reported_checks_complete"]
    assert report["staging_deploy_authorized"] is False
    assert report["production_deploy_authorized"] is False
    assert report["ci_result_cryptographically_verified"] is False
    assert report["operator_attestations_independently_verified"] is False
    assert len(report["report_sha256"]) == 64
    assert report == assess_release(evidence())


@pytest.mark.parametrize("changed,issue", [
    (("signer_is_separate_from_application", False), "audit_authority_not_isolated"),
    (("immutable_backup_independently_verified", False), "immutable_backup_unverified"),
    (("key_custody_independently_verified", False), "key_custody_unverified"),
    (("external_authorization_granted", False), "external_authorization_missing"),
])
def test_missing_prerequisite_denies_review_candidate(changed, issue):
    value = evidence()
    value[changed[0]] = changed[1]
    report = assess_release(value)
    assert not report["review_candidate"]
    assert issue in report["issues"]


def test_missing_skipped_or_failed_ci_blocks():
    value = evidence()
    value["checks"].pop()
    assert not assess_release(value)["review_candidate"]
    value = evidence()
    value["checks"][0]["status"] = "skipped"
    assert "not_successful_python_tests" in assess_release(value)["issues"]
    value["checks"][0]["status"] = "failure"
    assert not assess_release(value)["review_candidate"]


def test_bad_and_duplicate_evidence_is_rejected():
    value = evidence()
    value["checks"].append(value["checks"][0])
    with pytest.raises(ValidationError):
        assess_release(value)
    value = evidence()
    value["checks"][0]["key"] = "made_up_pass"
    with pytest.raises(ValueError, match="Unexpected"):
        assess_release(value)
    value = evidence()
    value["ci_run_reference"] = "https://not-github.example/runs/1"
    with pytest.raises(ValidationError):
        assess_release(value)
    value = evidence()
    value["commit_sha"] = "bad-commit"
    with pytest.raises(ValidationError):
        assess_release(value)
    value = evidence()
    value["production_approved"] = True
    with pytest.raises(ValidationError):
        assess_release(value)
