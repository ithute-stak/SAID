# SAID Intelligence — Phase 13 sandbox

This module extends simulated CEIR data-quality analysis with opaque evidence
provenance, append-only assessment snapshots, and an investigation queue.

## Features
- A central SAID admin records one simulated provenance record per observation,
  matching the registered hypothetical source exactly.
- The evidence reference is an opaque token, **not** a National ID, phone,
  subscriber identity, IMEI, location, external URL or evidence file.
- Assessments report same-token observation counts, number of mock sources and
  completeness of documented provenance.
- Confidence is limited to `insufficient_evidence` and
  `corroboration_required`. These labels describe review needs; they
  never claim verified fraud, altered IMEI or ownership.
- Assessments create append-only snapshots; rerunning an assessment does not
  overwrite older assessment history. This is API immutability only, not yet
  tamper-evident logging or protected DB-level append-only enforcement.
- The investigation queue lists the existing human-review cases for central
  administrators. Case review remains controlled by Phase 12 endpoints.

## Security boundaries
All endpoints require a centrally authenticated SAID admin. FORCE PostgreSQL
RLS protects the new tables, but a privileged database role can bypass access
controls. No carrier integrations or live operator messages are enabled.
IMEI HMAC equality tokens remain sensitive pseudonymous data and should
receive approved retention limits, rotation and key custody controls.

Future phases require legally approved evidence collection, role separation,
independent review, immutable audit chain, false-positive appeal, security
testing, and data-quality calibration against representative consented data.


## Phase 14 — Review dashboard

The responsive `/intelligence/` page is a controlled development interface.
Its HTML shell is public, but all investigations, indicator signals,
evidence provenance, assessments, and review mutations require the existing
central administrator authorization. The page never requests raw IMEIs.

The dashboard provides a case queue, counts for the current 100-item page,
individual observation indicators, provenance metadata, assessment snapshots,
an opt-in assessment action, and explicit one-time human review decisions.

Access tokens are held in browser tab memory and cleared on disconnect.
The page uses textContent rather than innerHTML to display untrusted values,
with a restrictive Content Security Policy and same-origin API requests.

**Limitations:** No production IdP login, reviewer-specific RBAC separation,
independent second approval, tamper-evident event ledger or configurable
retention enforcement has been implemented. These are future hardening phases;
a central admin currently holds the review permission. No real operator
data or blocking functionality exists.
