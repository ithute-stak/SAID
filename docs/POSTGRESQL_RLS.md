# SAID Phase 6 — PostgreSQL row-level security

Phase 6 enables and **FORCE**s PostgreSQL row-level security (RLS) on four
tables: `devices`, `theft_reports`, `ownership_claims`, `audit_events`.
Every record is restricted to its authorized institution. Child records
inherit scope from `devices`; audit records have their own institution ID.

## Application transaction context

The authenticated SAID principal is attached to the SQLAlchemy session. At
the beginning of **each transaction**, the `after_begin` listener calls
`set_config(..., true)` (transaction-local) to set:
- `said.institution` — identity-provider-signed institution claim
- `said.central` — true only for `said_admin` in `said-central`;
  development-only admin for isolated development testing

Absent context must fail closed. A shared connection pool cannot retain
another transaction's authorized tenant context.

## Security limits — important

PostgreSQL custom configuration parameters are **not tamper-proof**: anyone
with permission to execute arbitrary SQL using the application database role
can change them. RLS is therefore defense-in-depth, **not a substitute** for
parameterized queries, safe code, strict database grants, network isolation,
OIDC issuer controls and anti-injection safeguards. The runtime database
role must be non-superuser, `NOBYPASSRLS`, not a table owner, and must not
have schema-changing privileges. Use a separately protected migration role.
Test these invariants in deployment.

Existing `NULL`-institution records remain central-only until explicitly
reconciled. Inaccessible records appear absent, but PostgreSQL uniqueness
checks can still reveal a duplicate IMEI during registration; mitigate that
separately with privacy-preserving workflows and throttling.

Do not apply migration 0004 and run old API workers: those workers do not
initialize the transaction context and will be denied access. Roll out
compatible application code and migration together under a controlled
maintenance window. Always back up first. Never use destructive downgrades
against populated live data.

Real LCA, Vodacom, Econet and National ID integrations remain disabled.
