# SAID Phase 34 — Authenticated GitHub PR Review Evidence

SAID — Powered by Ithute Digital Solutions.

The read-only command:

```sh
export SAID_GITHUB_READ_TOKEN="a_scoped_read_only_token"
python -m said.github_review_evidence \
  --commit <40-character-PR-head-sha> \
  --pr <PR-number> \
  --security-login <github-login> \
  --operations-login <different-github-login> \
  --deployer-login <third-github-login>
```

It retrieves GitHub's PR metadata, up to 100 review events and up to 100
effective branch rules for `main` using fixed-origin authenticated HTTPS.
It requires an open non-draft PR from the SAID repository to `main`, matching
head SHA, distinct author, security reviewer, operations reviewer and deployer
logins, and fresh head-commit `APPROVED` reviews that have not been superseded
by a newer rejection. More than 99 review entries or rules fail closed rather
than silently accepting a truncated page.

The rule check requires GitHub to report `pull_request`,
`required_status_checks`, `non_fast_forward` and `deletion` effective
rules. It does **not** verify organization/enterprise bypass rights, all
ruleset precedence, institutional reviewer roles, signed human security
reviews, or formal deployment authority. Reviewer role names are supplied
by the operator and are not independently authenticated as institutional
roles. It also does not validate external telecom permissions.

All output flags for deployment and network operations remain false. The
command does not deploy, sign evidence, write to GitHub, or send data to
telecom networks. In CI, the GitHub responses are fully mocked; no actual
token or live network calls are used.

Further work must independently validate GitHub ruleset bypass actors,
external signoff authority and effective organization governance before
any production deployment decision.
