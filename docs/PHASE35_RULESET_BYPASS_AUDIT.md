# SAID Phase 35 — Ruleset Bypass and Governance Review

SAID — Powered by Ithute Digital Solutions.

This phase adds a read-only, fixed-repository GitHub API assessment of the ruleset inventory and individual ruleset details. Run:

```bash
export SAID_GITHUB_READ_TOKEN='scoped-read-only-token'
python -m said.ruleset_bypass_audit --commit <full-40-hex-sha>
```

The assessor rejects missing/incomplete list responses, mismatched detail IDs, inactive or ambiguously scoped main-branch rules, any listed bypass actors, missing pull-request review/status-check/non-fast-forward/deletion rules, fewer than two required approvers, and a missing `tests` status check. It does not change settings. It requires a GitHub token permitted to read repository ruleset detail endpoints.

These assertions are deliberately conservative. GitHub organization/enterprise bypass privileges, other ruleset scopes, review-account membership in formal security/operations teams, and real-world approval authority are **not exhaustively proven**. A successful report is security-review information only; it cannot authorize staging, production, a network action, or national CEIR operations. CI runs offline synthetic tests and does not authenticate an actual GitHub repository ruleset policy.
