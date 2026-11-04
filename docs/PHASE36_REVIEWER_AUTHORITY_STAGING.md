# SAID Phase 36 — Reviewer Authority and Staging Evidence

SAID, powered by Ithute Digital Solutions.

Phase 36 introduces two **read-only and non-authorizing** checks.

1. `python -m said.reviewer_authority --commit <SHA> --security-login <login> --operations-login <login> --author-login <login> --deployer-login <login> --pr-review-evidence /private/reviews/pr-evidence.json`

   This queries the GitHub organization team membership endpoints for
   `said-security-reviewers` and `said-operations-reviewers` using the
   scoped `SAID_GITHUB_READ_TOKEN` environment variable. Memberships
   must be active and independent from each other, the author and deployer.
   The input PR evidence must already report passing review checks and
   match the commit. Unknown or inaccessible GitHub responses fail closed.
   Teams must actually exist and the read token must have appropriate access.

2. `python -m said.staging_dossier --dossier /private/reviews/staging-dossier.json`

   The `said.mock.staging-dossier.v1` object supplies an exact commit SHA
   and structured CI, PR review, GitHub ruleset, reviewer team and audit-host
   reports. It checks exact commit consistency, explicit passing review flags,
   lack of contradictory authorization claims and an operator-supplied host
   readiness result. Inconsistent or incomplete evidence fails closed.

Neither GitHub team membership nor report consistency establishes legal
authority, identity credentials, independent infrastructure attestation,
immutable backup proofs, independent signer custody or national CEIR approval.
All staging, production and telecom-operation authorization flags are
hard-coded false. No deploy mechanism is present. CI tests use synthetic
responses and never access the actual organization or subscriber systems.

Future work should authenticate the full content of each referenced report,
verify GitHub team IDs and governance memberships with independent
organization policy, and obtain external operational/security approvals
outside the application.
