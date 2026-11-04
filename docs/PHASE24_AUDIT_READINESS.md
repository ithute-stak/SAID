# SAID Phase 24 — Audit Operations Readiness and Security Review

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase adds a **static**, conservative systemd configuration check,
operator-entered recovery objective assessment and **non-executing**
incident-response exercises for SAID's separate mock audit authority.

## Commands

From a separate, approved audit host or development environment:

```sh
python -m audit_authority.cli check-unit \
  --store /var/lib/said-audit/receipts.db \
  --unit-file deploy/audit-authority/said-audit-drill.service.example

python -m audit_authority.cli readiness \
  --store /var/lib/said-audit/receipts.db \
  --unit-file deploy/audit-authority/said-audit-drill.service.example \
  --assessment /private/audit/approved-assessment.json
```

The assessment JSON must contain exactly two objects: `objectives` and
`incident`. Objectives specify
`recovery_time_objective_minutes` (RTO),
`recovery_point_objective_minutes` (RPO),
`observed_recovery_duration_seconds`,
`observed_backup_age_seconds`, `recovery_test_passed`, and
`backup_integrity_passed`. **Measurements are supplied by an operator;**
the tool does not infer actual recovery times.

Incident exercises accept a scenario
(`receipt_store_corruption`, `backup_missing`,
`signing_key_suspected_compromise`, or `unauthorized_change`),
`evidence_preserved`, `signing_suspended`,
`independent_reviewer_assigned`, and an opaque
`escalation_reference`. These flags record simulated exercise outcomes,
not actual signing suspension or alert delivery.

The readiness command also requires the source audit database health check
to pass. Both commands return exit code 2 on assessed failure.

## Security checks

The unit checker conservatively checks the sample service's restricted
dedicated Unix user, strict filesystem sandbox, absence of environment
passphrase assignments, disabled IP connectivity, and limited writable
drill directory. It rejects additional unreviewed start/stop commands.
It does **not** evaluate dynamically applied systemd drop-ins, effective
permissions, firewall state, SELinux/AppArmor, live key custody or host
patch level. These must be independently inspected before deployment.

## Release readiness and sign-off

The checker never returns production approval. A trusted human governance
team must approve at least: isolated authority host and ownership; HSM/KMS
or independently controlled signing keys; signed public-key revocation
policy; externally immutable authenticated backup catalog and restore
exercise; independent alerts and escalation; actual RTO/RPO measurements;
legal review of audit evidence; national data protection requirements; and
an independently reviewed network and access-control design.

**No systemd unit was installed, no schedule started, no external storage
connected and no telecom network action is enabled.** This phase is mock-only,
not regulatory approval, external audit certification or verified proof
of recoverability.
