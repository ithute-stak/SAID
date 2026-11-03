# SAID Phase 7 — SAID Control internal web prototype

**Brand:** SAID — Secure Asset Identity & Detection, powered by Ithute
Digital Solutions.

URL after starting the development API: `http://localhost:8000/console/`.

The interface provides same-origin operations for institutional users:
- Device lookup by internal device ID.
- Unverified device registration with IMEI checksum validation on the API.
- Pending-review theft incident submission.
- Ownership evidence claim retrieval, submission and reviewer decision.

**Authentication:** A human operator manually supplies a short-lived bearer
token from a separately provisioned trusted OIDC identity provider. It is
held only in an in-memory JavaScript variable, never browser storage, cookies,
URLs or logs. Disconnect clears it. The frontend never accepts the legacy
development API key.

A first-party SAID SVG shield is embedded in the HTML. The dark navy,
blue and teal UI visibly identifies SAID as **Powered by Ithute**.
The console does not assume any LCA, Vodacom, Econet or other government
endorsement.

**Not yet delivered:** the citizen self-service SAID Protect application,
real account login/PKCE, a vetted identity provider, user session refresh
and logout at the identity provider, owner-granular authorization, uploads,
IMEI lookup by value, dealer inventory, network blocking or integration.

## Security considerations

The HTML shell and static assets are public, but business data and mutations
still pass the same institutional API authentication, role-based checks and
database-level RLS. We set a restrictive CSP for the HTML shell; deployments
must additionally enforce HTTPS, HSTS, CSRF posture appropriate to the chosen
identity mechanism, and abuse prevention. In production, replace token-paste
UX with an OAuth2 Authorization Code + PKCE flow or secure server-side
session/BFF using a trustworthy identity provider. This is not suitable for
unmanaged public terminals.

No public citizen device portal should be exposed before owner-specific
authentication and consent/verification workflows exist.

## Existing database correction

This milestone also ensures new theft-report and ownership-review audit events
carry the institution ID required by PostgreSQL RLS. Those operations remain
subject to the institution and role checks already in the backend.
