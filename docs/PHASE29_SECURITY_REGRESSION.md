# SAID Phase 29 — API Security Regression

Phase 29 tests mock CEIR API denial of anonymous and cross-institution requests, actor independence, malformed input, replayed reviews/appeals, and duplicate submissions. The status-proposal endpoint rolls back on revision conflict and atomically commits the proposal with its audit event.

Ephemeral PostgreSQL CI tests race four proposals on the same revision and verify a single winner. A rollback exercise checks that a simulated failure cannot leave a stray proposal event. These tests use synthetic data and cannot authorize real telecom operations, national CEIR integration, or certify production security.
