# Phase 9 — Consent-first ownership linking groundwork

**SAID, powered by Ithute Digital Solutions.**

A citizen can create an ownership inquiry, explicitly consent to an
independent ownership-linking review using consent text version
`SAID-LINK-CONSENT-v1`, view their own link intent, and withdraw it.

The intent links only the OIDC citizen *subject* and their own ownership
inquiry. It does NOT link to an actual device record and intentionally
cannot be "approved" by the current API.

## Security rules
- Signed citizen JWT with `citizen` role and `citizens` institution.
- Citizen is derived from token; cannot be provided by the browser.
- Inquiry must belong to that citizen and have category `ownership_inquiry`.
- One consent intent per inquiry; explicit versioned consent required.
- PostgreSQL FORCE RLS checks the same citizen subject, institution and
  related inquiry's ownership; SQLite API tests repeat boundary checks.
- Cross-subject reads and withdrawal are denied with 404.
- Withdrawn intents are terminal, retained only under configured policies.
- No IMEI, National ID, device identifiers or personal evidence appear in
  citizen link intent API payloads.

## What is still needed before genuine verified ownership
A legally authorized identity provider, a secure process for validating
proof-of-purchase and legitimate ownership, staff separation of duties,
dispute/appeal rights, signed review decisions, verified linkage to the
specific device record, and explicit enforcement of entitlement revocation
and data retention. Avoid promoting an evidence_supported claim alone to a
verified owner; that Phase 2 decision is not legal identity verification.

## Operational note
Do not enable public signup based on this development prototype. Use
OAuth2 Authorization Code + PKCE (or server-side BFF), not manual bearer
token entry, and apply rate limiting and legal-basis privacy controls.
