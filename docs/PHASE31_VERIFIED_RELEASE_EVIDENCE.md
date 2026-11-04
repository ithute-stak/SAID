# SAID Phase 31 — Verified GitHub Release Evidence

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase adds an **optional, read-only** GitHub API verifier. It requests
the exact GitHub Actions run, jobs, and main-branch protection via HTTPS,
and checks fields rather than trusting the operator's self-reported JSON.

## Usage

Grant a scoped, read-only GitHub token access to Actions and repository
administration metadata for the SAID repository (the exact permissions
needed to read branch protection depend on the GitHub organization policy).
Never commit the token or send it to the SAID FastAPI service or the separate
audit authority.

```sh
export SAID_GITHUB_READ_TOKEN="your_read_only_token"
python -m said.verified_release \
  --commit <exact_40_character_lowercase_commit_sha> \
  --run-id <github_actions_run_id>
```

The verifier checks that the workflow belongs to
`ithute-stak/SAID`, its name is `SAID CI`, its conclusion and
single expected job are completed successfully, the run is the first
attempt, and its head SHA exactly matches the requested commit.
All seven mandatory Python/PostgreSQL/SQLite/RLS/concurrency/fault tests
must appear once with completed success results. Missing or skipped steps
fail closed. A truncated jobs list or unexpected extra job fails closed.

The optional branch protection check reads the classic
`/branches/main/protection` endpoint and requires strict status checks,
an explicit `tests` context, at least one PR approval and nonbypass
by administrators. If unavailable or not configured, review candidacy
is denied. GitHub Rulesets and some bypass paths are **not** independently
evaluated by this version.

## Important limits

GitHub API responses are authenticated by HTTPS and the caller's token,
but these checks **are not a cryptographic attestation**. GitHub's API
and the account controlling workflow configuration remain trust
dependencies. They do not establish HSM custody, external immutable
backups, regulator permission or independently measured recovery goals.

A successful assessment returns only `review_candidate=true`.
`staging_deploy_authorized` and `production_deploy_authorized`
remain false; there is no deploy command, external network-blocking
integration, national CEIR certification or live carrier data feed.

The CI pipeline tests this module against fully synthetic fixture
responses and never requires a live GitHub token to pass.
