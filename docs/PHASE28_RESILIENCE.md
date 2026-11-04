# SAID Phase 28 — Failure Injection and Concurrency Resilience

SAID — Powered by Ithute Digital Solutions.

Phase 28 adds a PostgreSQL integration exercise that injects an exception between flushing mock appeal and audit-ledger rows and the transaction commit. The database must roll back both changes. A second exercise starts four concurrent appeal submissions for the same simulated investigation; exactly one must commit, and the event hash chain remains continuous and free of ghost events.

Unit tests cover rollback and conflict handling for PostgreSQL SQLSTATE 40P01 (deadlock), 40001 (serialization), 55P03 (lock unavailable), unique-constraint conflicts, and unknown connection errors. There are no automatic retries of privileged decisions.

The tests run exclusively against the ephemeral GitHub Actions PostgreSQL service, requiring an explicit safety environment marker. They do not target a deployed host, real subscriber records or telecom networks. Further readiness requires distributed load tests, independent security review and operator-approved integrations.
