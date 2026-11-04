# SAID Phase 27 — Serialized Case Transactions

SAID — Powered by Ithute Digital Solutions.

This phase standardizes case-first PostgreSQL locking across mock CEIR review, appeal creation/decisions, retention-plan creation/decisions, and oversight checkpoint/hold creation. A shared `lock_case()` locks the investigation row before reading or mutating dependent case state. The ledger append function retains this lock and verifies the full previous hash chain.

`commit_case()` rolls back on uniqueness conflicts, deadlocks (40P01), serialization failures (40001) and lock-not-available conflicts (55P03). It does **not** silently retry, because a full retry must reauthenticate and revalidate independent roles, case status, preservation holds and appeals.

The ephemeral PostgreSQL CI suite now tests seven competing audit-ledger writers, one winner from two competing review decisions, and simultaneous independent appeal and hold creation for an already reviewed mock case. Each event sequence and digest is checked afterward.

This does not guarantee arbitrary multi-host stress safety or address every possible cross-table ordering; it is a targeted concurrency improvement for the sandbox. SQLite does not implement `SELECT FOR UPDATE`. No deletion of evidence, telecom access, IMEI blocking, real CEIR feeds, or production identity provisioning occurs.
