# SAID Phase 23 — Offline Audit Operations and Monitoring

**SAID — Secure Asset Identity & Detection**, Powered by Ithute Digital Solutions.

This phase adds local audit-health checks, operator-provided backup
inventory comparisons and durable local JSONL recovery-drill reports.
Nothing is attached to the SAID API; no monitoring or scheduling is live.

## Commands

Run on a dedicated, independently managed audit authority host:

```bash
python -m audit_authority.cli health --store /var/lib/said-audit/receipts.db
python -m audit_authority.cli inventory --store /var/lib/said-audit/receipts.db \
  --inventory-directory /private/audit-backups \
  --inventory /private/approved-catalog.json
python -m audit_authority.cli drill-report \
  --store /var/lib/said-audit/receipts.db \
  --drill-directory /var/lib/said-audit/drills \
  --report-path /private/audit-reports/drill-events.jsonl
```

`health` reads the audit store without creating it. It checks SQLite
integrity, receipt metadata and local append-only triggers and returns a
critical status with exit code 2 when unhealthy.

`inventory` accepts a JSON catalog with version
`said.mock.backup-inventory.v1` and an `entries` list containing
`filename` and `sha256` fields. The operator must independently
authenticate that catalog. Checks reject duplicates and paths outside the
private inventory directory and verify each backup's digest and structure.
A missing or mismatched backup causes a critical response and exit code 2.

`drill-report` runs an isolated recovery drill and appends a minimal
success/failure record to a private local JSON Lines report file. It returns
exit code 2 for a failed drill. Reports omit receipt contents and signing
keys; they contain only outcome, timestamp, count, snapshot checksum or
error type. These local reports are not digitally signed or WORM.

## Escalation and deployment

A monitoring administrator can independently process exit code 2 and
explicit critical statuses to page an on-call security team. This
repository **does not** create remote alerts, schedule checks, provision
identities, enable systemd timers, transmit backups or contact operators.

Suggested response: (1) suspend signing if health fails; (2) preserve
the original database and all audit evidence; (3) investigate missing or
altered backups; (4) require an independent supervisor to approve a
restore exercise; (5) document resolution out of band.

The example weekly timer from Phase 22 remains inert. Do not activate
until the external audit-host team approves access, recovery objectives
and escalation rules. Use out-of-band signed inventories and secure
immutable off-site copies before production launch.

This remains a mock-only prototype: there is no external transparency log,
independent timestamp, legally certified custody, telecom network
integration, national CEIR approval or network blocking.
