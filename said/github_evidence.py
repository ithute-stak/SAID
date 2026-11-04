"""Read-only, authenticated GitHub API review of an exact SAID CI commit/run.

GitHub API TLS/token checks provide server-returned evidence, not signed
attestation, repository release authorization, or regulator approval.
"""
import argparse
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .release_gate import CI_WORKFLOW_STEPS

REPO = "ithute-stak/SAID"
WORKFLOW = ".github/workflows/ci.yml"
# GitHub Actions displays unnamed run steps with a "Run " prefix.
STEPS = (
    "Run python -m pytest -q",
    *CI_WORKFLOW_STEPS[1:],
    "Verify SAID security release workflow policy (no deployment)",
)


def github_json(path: str, token: str):
    """Fixed-origin GitHub GET. No redirects, arbitrary URLs or response secrets."""
    if not path.startswith("/repos/ithute-stak/SAID/"):
        raise ValueError("GitHub endpoint outside authorized repository")
    if not token:
        raise ValueError("An authenticated GitHub token is required")
    request = Request("https://api.github.com" + path, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "SAID-read-only-ci-evidence",
    })
    with urlopen(request, timeout=10) as response:
        if response.geturl() != request.full_url:
            raise ValueError("GitHub redirect rejected")
        if response.status != 200:
            raise ValueError("GitHub API did not return success")
        if int(response.headers.get("Content-Length", "0")) > 1000000:
            raise ValueError("Oversized GitHub API response")
        body = response.read(1000001)
        if len(body) > 1000000:
            raise ValueError("Oversized GitHub API response")
        return json.loads(body)


def verify_run(commit_sha: str, run_id: int, *, token: str, fetch=github_json) -> dict:
    """Require exact SHA/run, expected workflow and all critical steps successful."""
    if not re.fullmatch("[0-9a-f]{40}", commit_sha):
        raise ValueError("Invalid full commit SHA")
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id <= 0:
        raise ValueError("Invalid workflow run ID")
    prefix = "/repos/" + REPO
    try:
        run = fetch(prefix + f"/actions/runs/{run_id}", token)
        jobs = fetch(prefix + f"/actions/runs/{run_id}/jobs?per_page=100", token)
    except (HTTPError, URLError, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        return {"passed": False, "issues": ["github_api_unavailable_or_invalid"],
                "source": "github_api", "staging_deploy_authorized": False,
                "production_deploy_authorized": False}
    issues = []
    if run.get("head_sha") != commit_sha:
        issues.append("commit_sha_mismatch")
    if run.get("repository", {}).get("full_name") != REPO:
        issues.append("wrong_repository")
    if run.get("path") != WORKFLOW:
        issues.append("unexpected_workflow")
    if run.get("event") != "pull_request":
        issues.append("unexpected_event")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        issues.append("run_not_successful")
    if run.get("id") != run_id:
        issues.append("run_id_mismatch")
    if jobs.get("total_count") != 1 or len(jobs.get("jobs", [])) != 1:
        issues.append("unexpected_job_count")
    else:
        job = jobs["jobs"][0]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            issues.append("job_not_successful")
        steps = job.get("steps", [])
        if len({s.get("name") for s in steps}) != len(steps):
            issues.append("duplicate_step_names")
        by_name = {s.get("name"): s for s in steps}
        for name in STEPS:
            step = by_name.get(name)
            if step is None or step.get("status") != "completed" or step.get("conclusion") != "success":
                issues.append("missing_or_failed_step_" + name)
    return {"passed": not issues, "issues": issues,
            "commit_sha": commit_sha, "run_id": run_id,
            "source": "authenticated_github_api",
            "github_response_not_cryptographically_signed": True,
            "branch_protection_verified": False,
            "staging_deploy_authorized": False,
            "production_deploy_authorized": False,
            "external_telecom_authorization_verified": False}


def main():
    parser = argparse.ArgumentParser(description="Verify exact SAID GitHub CI run (read only)")
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-id", type=int, required=True)
    args = parser.parse_args()
    token = os.getenv("SAID_GITHUB_READ_TOKEN", "")
    result = verify_run(args.commit_sha, args.run_id, token=token)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["passed"] else 2)


if __name__ == "__main__":
    main()
