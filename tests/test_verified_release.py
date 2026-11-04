"""Phase 31: verification of GitHub API evidence and no-deployment guarantees."""
from unittest.mock import patch

import pytest

from said.verified_release import (
    REQUIRED_STEPS, fetch_and_verify, verify_branch_protection, verify_run,
)

SHA = "a" * 40
RUN = 456789

def successful():
    run = {
        "id": RUN, "head_sha": SHA, "name": "SAID CI",
        "event": "pull_request", "status": "completed", "conclusion": "success",
        "repository": {"full_name": "ithute-stak/SAID"},
        "run_attempt": 1,
    }
    jobs = {"total_count": 1, "jobs": [{
        "name": "tests", "run_id": RUN, "status": "completed",
        "conclusion": "success",
        "steps": [{"name": name, "status": "completed", "conclusion": "success"}
                  for name in REQUIRED_STEPS],
    }]}
    protection = {
        "required_status_checks": {"strict": True,
            "checks": [{"context": "tests", "app_id": 15368}]},
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "enforce_admins": {"enabled": True}
    }
    return run, jobs, protection

def test_success_is_only_review_candidate():
    run, jobs, protection = successful()
    evaluated = verify_run(run, jobs, SHA, RUN)
    assert evaluated["checks_verified"]
    assert evaluated["production_deploy_authorized"] is False
    assert evaluated["cryptographic_attestation_verified"] is False
    assert verify_branch_protection(protection)["verified_policy_fields"]

    def github_fixture(path, token):
        assert token == "synthetic-read-token"
        if path.endswith("/protection"):
            return protection
        if path.endswith("/jobs"):
            return jobs
        return run

    with patch("said.verified_release.github_json", side_effect=github_fixture):
        report = fetch_and_verify(SHA, RUN, "synthetic-read-token")
    assert report["review_candidate"]
    assert report["branch_protection_verified"]
    assert not report["staging_deploy_authorized"]
    assert len(report["report_sha256"]) == 64

@pytest.mark.parametrize("overrides,issue", [
    ({"head_sha": "b" * 40}, "commit_mismatch"),
    ({"id": 1}, "run_id_mismatch"),
    ({"status": "in_progress"}, "workflow_not_successful"),
    ({"conclusion": "failure"}, "workflow_not_successful"),
    ({"name": "Other CI"}, "workflow_mismatch"),
    ({"event": "workflow_dispatch"}, "unapproved_event_type"),
    ({"run_attempt": 2}, "rerun_requires_manual_review"),
    ({"repository": {"full_name": "attacker/SAID"}}, "repository_mismatch"),
])
def test_run_identity_must_match(overrides, issue):
    run, jobs, _ = successful()
    run.update(overrides)
    report = verify_run(run, jobs, SHA, RUN)
    assert not report["checks_verified"]
    assert issue in report["issues"]

def test_no_missing_or_skipped_checks_and_pagination():
    run, jobs, _ = successful()
    jobs["jobs"][0]["steps"][1]["conclusion"] = "skipped"
    assert not verify_run(run, jobs, SHA, RUN)["checks_verified"]
    run, jobs, _ = successful()
    jobs["jobs"][0]["steps"].pop()
    assert not verify_run(run, jobs, SHA, RUN)["checks_verified"]
    run, jobs, _ = successful()
    jobs["total_count"] = 2
    assert "job_page_incomplete" in verify_run(run, jobs, SHA, RUN)["issues"]
    run, jobs, _ = successful()
    jobs["jobs"].append(jobs["jobs"][0])
    assert "unexpected_job_count" in verify_run(run, jobs, SHA, RUN)["issues"]

def test_branch_policy_missing_or_inaccessible_is_fail_closed():
    run, jobs, protection = successful()
    protection["enforce_admins"]["enabled"] = False
    assert not verify_branch_protection(protection)["verified_policy_fields"]
    run, jobs, _ = successful()
    with patch("said.verified_release.github_json", side_effect=[
        run, jobs, ValueError("missing protection")
    ]):
        report = fetch_and_verify(SHA, RUN, "synthetic-read-token")
    assert report["checks_verified"]
    assert not report["review_candidate"]
    assert report["branch_protection_issues"] == ["branch_protection_not_accessible"]

def test_invalid_revision_ref_rejected_before_network():
    with pytest.raises(ValueError):
        fetch_and_verify("not-sha", RUN, "synthetic-read-token")
    with pytest.raises(ValueError):
        fetch_and_verify(SHA, 0, "synthetic-read-token")
