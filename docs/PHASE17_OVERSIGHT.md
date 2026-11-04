# SAID Phase 17 — Supervisory oversight (mock CEIR only)

Phase 17 introduces an isolated oversight dashboard and central-only API
for appeals queue summaries, per-investigation **local** audit checkpoints
and retained-evidence legal-hold flags. It is not a live national CEIR.

## Independence

An auditor must have central SAID admin membership and `ceir_auditor`
(or `ceir_supervisor`) role. Checkpoints cannot be created by the
investigation opener or its original reviewer. A supervisor can register
one legal hold per mock investigation if they are not the opener/reviewer.

## Local checkpoints

Checkpoints snapshot the current validated SHA-256 review-ledger head,
sequence and actor. Replays are idempotent. Verification checks that saved
checkpoints match the corresponding historic sequence. PostgreSQL triggers
reject UPDATE/DELETE on checkpoint and hold tables for ordinary DML roles.
A database owner can still alter controls or recreate both the ledger and
checkpoints: **no independent external audit anchoring is claimed**.
Checkpoint records are intended for later secure export to independent
tamper-resistant storage.

## Retention

Legal holds are active flags only. The existing retention preview stays
non-destructive, and no deletion or automated purge endpoint is exposed.
Retention execution requires independently approved legal-basis rules,
hold release procedure, appeal review, safe deletion sequencing, tamper-
resistant external anchors and tests. Legal-hold records intentionally
cannot be released through the present sandbox API.

## Operational limitations

UI shell is publicly loadable, while all data requires central role-based
OIDC. The dashboard uses a manually pasted bearer token in tab memory,
so it is limited to controlled development environments. No real operator
transports, mobile subscribers, IMEI blocking, national identity provider
or CEIR compliance certification exists.
