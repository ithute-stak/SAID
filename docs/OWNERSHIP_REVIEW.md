# Phase 2 — Ownership evidence-review prototype

SAID now supports an **admin-only evidence-review workflow**, not National ID verification.

## API (requires X-Admin-Key)
- `POST /api/v1/ownership/claims` — submit a reference to an ownership-evidence item associated with a device
- `GET /api/v1/ownership/claims/{claim_id}` — view a claim's review state
- `POST /api/v1/ownership/claims/{claim_id}/review` — select `evidence_supported` or `evidence_rejected`

This prototype deliberately accepts *opaque references* rather than raw National ID, scanned documents, or applicant personal details. They still need protection as potentially linkable personal data.

## What it does NOT do
- Evidence review **does not** verify National ID or legal device ownership.
- Device `verification_status` remains `unverified`.
- It does not contact Home Affairs, Vodacom, Econet or LCA.
- It does not create a transferable ownership certificate, authorize network blocking, or support public applicant access.
- A device is limited to one claim during Phase 2; disputes, corrections and appeals need a separately audited workflow.

## Before deployment
Add database migrations, OAuth2/OIDC authentication, MFA, reviewer identity and segregation of duties, permissions per organization and case, secure evidence storage, retention and deletion schedules, idempotency, concurrency control, and supervised verification services. This is a deliberately restricted development milestone.
