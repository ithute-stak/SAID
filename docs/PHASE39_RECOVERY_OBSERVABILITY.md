# SAID Phase 39 — Recovery Drill and Observability Policy

This is an **offline evaluator of synthetic, operator-supplied records**, not a backup
or restoration system. It cannot open a database, restore data, collect live
telemetry, or authorize a deployment.

## Recovery-drill evidence

Run `python -m said.recovery_drill --drill /private/evidence/drill.json`
with a JSON document containing `schema: said.mock.recovery-drill.v1`,
an exact commit SHA, synthetic source and disposable staging target, declared
backup/download SHA-256 and restored/expected snapshot SHA-256 checksums,
timezone-aware backup point, incident and restoration timestamps, RPO/RTO
objectives, database consistency checks, audit-chain verification, restricted
role and blocked telecom egress declarations, and a witness reference.

A passing result means the **supplied record** meets declared RPO/RTO and
integrity requirements. It does not verify actual backup bytes, prove a
restoration occurred, authenticate the witness, establish the immutable
storage of backups, or verify external keys. All release approvals remain
false.

## Observability policy

Run `python -m said.observability_gate --snapshot /private/evidence/monitor.json`.
The synthetic-only JSON record contains `schema: said.mock.observability.v1`,
a commit SHA, timestamp, last successful backup and drill times, API request
and error counters, p95 latency, application/database/audit health, security
alerts and routing state.

Conservative thresholds: telemetry at most 10 minutes old, backups at most
24 hours old, drill at most 30 days old, API error rate no more than 1%,
p95 latency no more than 1500 ms, zero unacknowledged security events, and
health/routing declared verified. Unknown or privileged production-only
data sources are rejected. No IMEI, subscriber or personal data is needed.

## Required independent follow-up

An authorized operator must perform a **genuine isolated restore** with
synthetic data and verify database correctness; a separate auditor must
authenticate the evidence, backup origin and retained snapshots. A monitoring
team must instrument alerts and conduct an actual alert-delivery exercise.
Never restore over production, change live subscriber information, enable
carrier egress or treat this self-reported evaluation as deployment approval.
