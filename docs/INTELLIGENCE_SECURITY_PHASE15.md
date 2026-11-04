# SAID Intelligence — Phase 15 security hardening

SAID's CEIR remains a **simulation**; no operator integrations or network
blocking, location monitoring, identity verification or adverse actions.

## Independent reviewer controls

A central SAID administrator opens mock investigations. Completing a review
requires a central SAID administrator **with the additional `ceir_reviewer`
role** and a distinct validated OIDC subject from the case opener. This
rejects self-review even when the operator has both roles. Existing cases
with unknown creator are deliberately not reviewable until a separately
authorized reconciliation procedure is developed.

## Tamper-evident event trail

New investigation creation and review decisions append ordered records with
SHA-256 hashes chained to previous events. A verification endpoint recomputes
every hash, rejects gaps and reports altered rows. The PostgreSQL table has
FORCE RLS, and a database trigger refuses UPDATE/DELETE even by DML roles.
A schema owner/superuser could still disable controls, recreate a chain or
alter timestamps; therefore **this is not an independent immutable audit
service**, and an external checkpoint/signature is a future requirement.

## Retention governance

`SAID_MOCK_RETENTION_DAYS` configures the bounded 7–365-day
retention **preview** window (default 90 days). The central-only endpoint
returns up to 100 old synthetic observation IDs as a non-destructive
report; it does not delete, anonymize, or bypass legal holds. Actual
automatic retention enforcement, approval workflows, auditable cleanup
and cryptographic key rotation remain pending.

## Deployment

Deploy the migration with a separate protected schema owner. A runtime
role must be non-superuser and NOBYPASSRLS, lack DDL grants, and must not
own the review ledger. Operators need distinct authenticated OIDC subjects;
development-admin identity is not suitable for split-role review.
All documentation and data refer to *mock sources only*.
