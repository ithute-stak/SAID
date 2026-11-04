# SAID Phase 16 — Governance and appeals

This work models *mock* appeals on already-reviewed CEIR investigations.
No decision affects a device's status, creates an operator message, determines
IMEI modification or theft, or enables blocking.

## Separation of duties

The investigator opens a case, a distinct person with `ceir_reviewer`
reviews it, a third person with `ceir_appeals_officer` can open one appeal,
and a fourth person with `ceir_supervisor` records the outcome. Each role
also needs central SAID administrator affiliation. The appeal request cannot
originate from the investigator or original reviewer. The supervisor cannot
be any of the three previous actors. Unknown review history fails closed.

An appeal records an opaque reason reference, then an independent supervisor
may choose `original_review_upheld` or `returned_for_further_review`.
This doesn't rewrite the initial finding, reopen the original case, or grant
device access. One appeal per case is allowed in the prototype.

## Audit and retention

Appeal open/decision events extend Phase 15's per-investigation hash chain.
Integrity checks detect missing, changed or out-of-sequence events. This is
not external immutability, and a schema owner could still rebuild a chain.

Retention remains **non-destructive**. The old observations preview never
deletes evidence or defeats a legal hold. Real retention execution must
account for appeals, open investigations, approval by a different operator,
export, hold metadata, and externally anchored audit checkpoints before it
can be safely enabled.

## Further requirements

A national deployment needs authorized appeals policy, claimant identity
and notification channels, due process, legal hold, external audit anchoring,
data protection assessment, real user provisioning and operational security
review. No LCA, Vodacom or Econet integration is claimed.
