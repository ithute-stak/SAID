"""Phase 31 GitHub API evidence verification for a specific SAID commit.

Authenticates API transport through TLS and checks returned fields. It does
not constitute cryptographic GitHub attestation or deployment authorization.
Never sends a GitHub token to the SAID API or independent audit signer.
"""
import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request

class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward a read token to any redirected destination."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("GitHub API redirect rejected")


from said.release_gate import CI_WORKFLOW_STEPS

REPO = "ithute-stak/SAID"
EXPECTED_JOB = "tests"
EXPECTED_WORKFLOW = "SAID CI"
REQUIRED_STEPS = (
    "Run python -m pytest -q",
    *CI_WORKFLOW_STEPS[1:],
)
EXPECTED_ACTIONS = "https://api.github.com"
SHA = re.compile(r"^[0-9a-f]{40}$")
RUN_ID = re.compile(r"^[1-9][0-9]*$")
MAX_RESPONSE = 2_000_000


def github_json(path: str, token: str) -> dict:
    """Allow only fixed GitHub API path segments; enforce response size."""
    if not re.fullmatch(r"/repos/ithute-stak/SAID/(actions/runs/[0-9]+(?:/jobs)?|branches/main/protection|pulls/[1-9][0-9]*(?:/reviews\\?per_page=100)?|rules/branches/main\\?per_page=100)", path):
        raise ValueError("Unexpected GitHub API path")
    request = urllib.request.Request(
        EXPECTED_ACTIONS + path,
        headers={"Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Authorization": "Bearer " + token,
                 "User-Agent": "said-release-verifier/0.31"})
    with urllib.request.build_opener(RejectRedirects()).open(request, timeout=10) as response:
        if response.status != 200:
            raise ValueError("GitHub response was not successful")
        payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ValueError("GitHub response too large")
    value = json.loads(payload)
    if not isinstance(value, (dict, list)):
        raise ValueError("Unexpected GitHub response")
    return value


def verify_run(run: dict, jobs: dict, commit_sha: str, run_id: int) -> dict:
    """Require exact commit, successful completed CI job, and every test step."""
    if not SHA.fullmatch(commit_sha) or isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
        raise ValueError("Invalid requested commit or run")
    problems = []
    if run.get("id") != run_id:
        problems.append("run_id_mismatch")
    if run.get("head_sha") != commit_sha:
        problems.append("commit_mismatch")
    if run.get("name") != EXPECTED_WORKFLOW:
        problems.append("workflow_mismatch")
    if run.get("path") != ".github/workflows/ci.yml":
        problems.append("workflow_path_mismatch")
    event = run.get("event")
    if event == "pull_request":
        pull_requests = run.get("pull_requests")
        if not isinstance(pull_requests, list) or not any(
            isinstance(pr, dict) and
            pr.get("base", {}).get("ref") == "main" and
            pr.get("head", {}).get("sha") == commit_sha
            for pr in pull_requests
        ):
            problems.append("pull_request_main_base_not_verified")
    elif event == "push":
        if run.get("head_branch") != "main":
            problems.append("unexpected_push_branch")
    else:
        problems.append("unapproved_event_type")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        problems.append("workflow_not_successful")
    if run.get("repository", {}).get("full_name") != REPO:
        problems.append("repository_mismatch")
    if run.get("run_attempt") != 1:
        problems.append("rerun_requires_manual_review")
    if not isinstance(jobs.get("jobs"), list):
        problems.append("jobs_missing")
        job_list = []
    else:
        job_list = jobs["jobs"]
    if jobs.get("total_count") != len(job_list):
        problems.append("job_page_incomplete")
    if len(job_list) != 1:
        problems.append("unexpected_job_count")
    for job in job_list:
        if job.get("run_id") != run_id or job.get("name") != EXPECTED_JOB:
            problems.append("job_identity_mismatch")
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            problems.append("job_not_successful")
        steps = job.get("steps")
        if not isinstance(steps, list):
            problems.append("job_steps_missing")
            steps = []
        names = [step.get("name") for step in steps if isinstance(step, dict)]
        if len(names) != len(set(names)):
            problems.append("duplicate_job_steps")
        for name in REQUIRED_STEPS:
            matches = [step for step in steps if step.get("name") == name]
            if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
                problems.append("required_step_not_successful:" + name)
    return {
        "schema": "said.mock.github-run-verification.v1",
        "repo": REPO, "commit_sha": commit_sha, "run_id": run_id,
        "checks_verified": not problems, "issues": sorted(set(problems)),
        "github_api_fields_checked": True,
        "cryptographic_attestation_verified": False,
        "branch_protection_verified": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
        "telecom_operations_enabled": False,
    }


def verify_branch_protection(protection: dict) -> dict:
    """Optional branch-policy inspection; main must demand reviews and checks."""
    issues = []
    required = protection.get("required_status_checks") or {}
    checks = required.get("checks") or []
    if not required.get("strict") or not isinstance(checks, list) or not any(
        c.get("context") == EXPECTED_JOB for c in checks if isinstance(c, dict)
    ):
        issues.append("required_strict_ci_check_missing")
    reviews = protection.get("required_pull_request_reviews") or {}
    if not isinstance(reviews.get("required_approving_review_count"), int) or (
        reviews.get("required_approving_review_count", 0) < 1
    ):
        issues.append("required_independent_pr_review_missing")
    if protection.get("allow_force_pushes", {}).get("enabled"):
        issues.append("force_pushes_allowed")
    if protection.get("allow_deletions", {}).get("enabled"):
        issues.append("protected_branch_deletion_allowed")
    if not protection.get("enforce_admins", {}).get("enabled"):
        issues.append("admins_can_bypass_branch_protection")
    return {"verified_policy_fields": not issues, "issues": issues,
            "rulesets_or_other_bypass_routes_checked": False}


def fetch_and_verify(commit_sha: str, run_id: int, token: str) -> dict:
    if not SHA.fullmatch(commit_sha) or run_id <= 0:
        raise ValueError("Invalid commit SHA or run ID")
    run = github_json(f"/repos/{REPO}/actions/runs/{run_id}", token)
    jobs = github_json(f"/repos/{REPO}/actions/runs/{run_id}/jobs", token)
    result = verify_run(run, jobs, commit_sha, run_id)
    try:
        protection = github_json(f"/repos/{REPO}/branches/main/protection", token)
        policy = verify_branch_protection(protection)
        result["branch_protection_verified"] = policy["verified_policy_fields"]
        result["branch_protection_issues"] = policy["issues"]
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError, TimeoutError):
        result["branch_protection_issues"] = ["branch_protection_not_accessible"]
    result["review_candidate"] = (result["checks_verified"] and
                                  result["branch_protection_verified"])
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["report_sha256"] = hashlib.sha256(canonical).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description="SAID verified GitHub CI evidence (review only)")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()
    if not SHA.fullmatch(args.commit) or args.run_id <= 0:
        parser.error("Expected 40-char lowercase SHA and positive run ID")
    token = os.getenv("SAID_GITHUB_READ_TOKEN", "")
    if not token:
        parser.error("SAID_GITHUB_READ_TOKEN is required (read-only)")
    try:
        result = fetch_and_verify(args.commit, args.run_id, token)
    except (urllib.error.HTTPError, urllib.error.URLError, ValueError,
            json.JSONDecodeError, TimeoutError) as exc:
        # Do not expose tokens, URLs or API response bodies in diagnostics.
        print(json.dumps({"verified": False, "error_type": type(exc).__name__,
                          "staging_deploy_authorized": False,
                          "production_deploy_authorized": False}))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["review_candidate"] else 2)


if __name__ == "__main__":
    main()
