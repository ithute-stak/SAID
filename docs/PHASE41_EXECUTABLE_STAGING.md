# SAID Phase 41 — Executable Ephemeral Staging Exercises

Phase 41 adds three **actually executed** CI exercises, confined to synthetic data.

1. `python tests/ci_asgi_staging_exercise.py`: 160 concurrent in-process ASGI requests (16 concurrent) exercise `/health` and unauthorized device reads, measure p95 and check expected status codes. These metrics reflect in-process application handling, **not network/server staging load**. A generous 5-second p95 smoke ceiling is a regression guard, not a service-level objective.
2. `python tests/ci_postgres_restore_drill.py`: requires the exact CI PostgreSQL connection settings, test-mode markers, and an initially absent `said_restore_ci_phase41` database. Creates a synthetic marker, runs **real pg_dump and pg_restore** from the disposable GitHub service into a new disposable DB, verifies the marker, migration revision and real FK constraints, records backup byte size and SHA-256, and drops only its own newly created target. It does not access a deployed or production database. It cannot verify real encrypted offsite backups.
3. `python -m said.alert_drill`: exercises real error-condition detection and notification delivery to a local **in-memory** sink. It does not contact an external pager, email or monitoring service.

GitHub Actions provisions an ephemeral PostgreSQL 16 service, installs a PostgreSQL client and runs the tests after migrations and other database tests. CI does not access public staging servers or carrier networks.

This validates executable CI paths, not infrastructure independence, actual end-to-end HTTPS or external alert delivery. SAID staging/production deployment and all telecommunications operations remain disabled. The next step is an explicitly approved isolated staging host with secrets/identity controls, monitored load, offsite backup recovery, alert-delivery proof and independent security review.
