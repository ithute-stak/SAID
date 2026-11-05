# SAID Phase 43 — Staging Isolation Escape-Path Hardening

Phase 43 strengthens Phase 42's **offline** Docker Compose configuration validator. It rejects unexpected networks or secrets, external or attachable networks, public ports, host/device escape surfaces, added Linux capabilities, extra API volumes, unapproved PostgreSQL mounts, locally built images, interactive containers, missing CPU limits, and altered staging project identity.

Run `python -m pytest -q tests/test_phase43_staging_escape.py`. The CI suite also continues rendering `compose.staging.yml` through Docker Compose and applying `said.staging_compose_policy`.

## Evidence limitations

These are deterministic configuration checks and negative tests, **not** a real Docker deployment, firewall audit, penetration test, image provenance check, secret-store assessment, live identity-provider validation, backup restore or externally delivered security alert.

**No staging or production authorization is granted.** Carrier connections, real device blocking, CEIR operations and national integrations remain disabled. A future phase must implement and independently exercise an approved staging runtime and record signed, timestamped external evidence.
