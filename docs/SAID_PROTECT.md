# SAID Protect — Phase 8 limited citizen prototype

SAID Protect is a **separate, mobile-friendly citizen intake interface**.
The first release supports only *manual-review inquiries*, not verified
ownership, registration of a new phone, network-location tracking, SIM
monitoring, ownership transfer, or network blocking.

## Isolation

Citizen API tokens must be signed by the configured institutional OIDC
issuer, have the `citizen` role and `said_institution=citizens`, and carry a
stable non-reassignable subject. The subject must be unique within the
configured issuer, so identity-provider migrations need an explicit mapping.

Requests are stamped from the validated access-token subject. The API
ignores attempts to pass a different subject in the submitted JSON.
PostgreSQL independently enforces subject-scoped RLS; users cannot list or
retrieve another citizen's requests even if an ID is guessed. A subject
scoped to `citizens` does not get access to the telecom/device tables.

The user can submit an **opaque reference** only (letters, digits, underscore
or dash), with clear instructions *not* to enter National IDs, IMEIs, SIM
details or phone numbers. No proof-of-ownership determination is made.

The admin-only device registry and claims workflows are unchanged.

## Production blockers

A vetted citizen identity provider and OAuth Authorization Code + PKCE
(or a secure session BFF), MFA where appropriate, privacy notices, data
retention, public rate limits, identity recovery, anti-abuse controls and
identity-to-legal-person validation are needed before accepting real
citizen intake. There is no real SAID Protect enrollment provider yet.

The prototype UI uses a manually supplied bearer token **in browser
memory only** and can be deployed only in a controlled development
environment. The frontend does not implement login, self-registration,
access token refresh or actual device registration.

## Proposed next phase

Build a protected ownership-linking decision process with approved evidence,
split roles, appeals and audit verification before showing personal registered
devices or allowing incident actions on them.
