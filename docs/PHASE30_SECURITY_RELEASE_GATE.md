# SAID Phase 30 — Security Release Gate

SAID, powered by Ithute Digital Solutions.

Phase 30 introduces a conservative offline release-evidence assessor and a CI workflow-policy structural check. Run `python -m said.release_gate --workflow .github/workflows/ci.yml` to check that Python tests, SQLite and PostgreSQL migrations, restricted-role RLS, concurrent case writes, fault-injection rollback, and status revision checks remain in CI.

An optional `--evidence /private/approved/release-evidence.json` reads an operator-provided JSON object with schema `said.mock.release-evidence.v1`, a 40-character commit SHA, a GitHub Actions run URL, and seven check entries keyed `python_tests`, `sqlite_migration`, `postgres_constraints`, `postgres_restricted_rls`, `case_concurrency`, `fault_rollback`, and `revision_concurrency`. Each must report `success` with an evidence reference. The report also requires asserted separation of signer and app, independently verified immutable backups and key custody, and external authorization. Missing or failed entries prevent even a *review candidate*.

**Important:** The assessor does not query GitHub or authenticate those claims. Even a passing report marks staging and production authorization false, and emits an unsigned SHA-256 content digest, not independent attestation. Effective host restrictions, actual immutable storage, valid keys, third-party permissions, and regulatory authorization require separate verification and approval. Nothing in this phase deploys infrastructure, enables network blocking, or makes SAID a national CEIR.
