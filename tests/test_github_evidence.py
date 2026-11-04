"""No-network regression tests of authenticated GitHub CI evidence verification."""
import pytest

from said.github_evidence import STEPS, verify_run, github_json

SHA = "a" * 40
RID = 123456

def samples():
    run = {
        "id": RID, "head_sha": SHA,
        "repository": {"full_name": "ithute-stak/SAID"},
        "path": ".github/workflows/ci.yml",
        "event": "pull_request", "status": "completed", "conclusion": "success",
    }
    jobs = {"total_count": 1, "jobs": [{
        "status": "completed", "conclusion": "success",
        "steps": [{"name": name, "status": "completed", "conclusion": "success"}
                  for name in STEPS],
    }]}
    return run, jobs

def verify(run, jobs):
    def fetch(path, token):
        assert token == "synthetic-read-only-token"
        assert path.startswith("/repos/ithute-stak/SAID/actions/runs/" + str(RID))
        return jobs if "/jobs?" in path else run
    return verify_run(SHA, RID, token="synthetic-read-only-token", fetch=fetch)

def test_valid_run_is_only_ci_verification():
    run, jobs = samples()
    result = verify(run, jobs)
    assert result["passed"] is True
    assert result["branch_protection_verified"] is False
    assert result["staging_deploy_authorized"] is False
    assert result["production_deploy_authorized"] is False

@pytest.mark.parametrize("field, value, issue", [
    ("head_sha", "b" * 40, "commit_sha_mismatch"),
    ("path", ".github/workflows/other.yml", "unexpected_workflow"),
    ("event", "workflow_dispatch", "unexpected_event"),
    ("status", "in_progress", "run_not_successful"),
    ("conclusion", "failure", "run_not_successful"),
    ("id", RID + 1, "run_id_mismatch"),
])
def test_run_identity_mismatch_fails_closed(field, value, issue):
    run, jobs = samples()
    run[field] = value
    result = verify(run, jobs)
    assert not result["passed"]
    assert issue in result["issues"]

def test_wrong_repository_is_rejected():
    run, jobs = samples()
    run["repository"]["full_name"] = "attacker/SAID"
    assert "wrong_repository" in verify(run, jobs)["issues"]

def test_missing_failed_or_skipped_steps_reject():
    for edit in ("missing", "skipped", "failure"):
        run, jobs = samples()
        if edit == "missing":
            jobs["jobs"][0]["steps"].pop()
        else:
            jobs["jobs"][0]["steps"][0]["conclusion"] = edit
        assert not verify(run, jobs)["passed"]

def test_extra_jobs_and_incomplete_job_fail():
    run, jobs = samples()
    jobs["total_count"] = 101
    assert "unexpected_job_count" in verify(run, jobs)["issues"]
    run, jobs = samples()
    jobs["jobs"][0]["status"] = "in_progress"
    assert "job_not_successful" in verify(run, jobs)["issues"]

def test_unknown_or_unreachable_api_fails_closed():
    def fails(path, token):
        raise OSError("synthetic network failure")
    result = verify_run(SHA, RID, token="synthetic-read-only-token", fetch=fails)
    assert result["passed"] is False
    assert "github_api_unavailable_or_invalid" in result["issues"]

def test_invalid_commit_and_token_rejected():
    with pytest.raises(ValueError):
        verify_run("bad", RID, token="fake", fetch=lambda path, token: {})
    with pytest.raises(ValueError):
        verify_run(SHA, 0, token="fake", fetch=lambda path, token: {})
    with pytest.raises(ValueError):
        github_json("/repos/another/repo/actions/runs/1", "fake")
    with pytest.raises(ValueError):
        github_json("/repos/ithute-stak/SAID/actions/runs/1", "")
