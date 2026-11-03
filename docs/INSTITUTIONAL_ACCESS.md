# Phase 4: institutional identity and access

The SAID API can now validate signed OIDC access tokens using a configured issuer,
audience, JWKS URL, and institutional role claim. This is an integration boundary,
**not** an operational identity provider or completed national identity integration.

## Configuration
- `SAID_ENVIRONMENT=production` disables the legacy development API key.
- `SAID_OIDC_ISSUER` must match the JWT `iss`.
- `SAID_OIDC_AUDIENCE` must match the JWT `aud`.
- `SAID_OIDC_JWKS_URL` is a trusted, administrator-configured HTTPS JWKS endpoint.

Tokens must carry `said_roles` (list of strings) and `said_institution`
(nonempty string). SAID validates the signature (RS256 or ES256), issuer,
audience, expiration, issue time and subject. Tokens from other issuers are rejected.

### Authorization roles (prototype)
| Role | Prototype permission |
|---|---|
| `said_admin` | All existing admin and evidence-review endpoints |
| `registrar` | Existing registration endpoints; further splitting planned |
| `case_worker` | Existing case endpoints; further splitting planned |
| `owner_reviewer` | Ownership evidence decisions only |

The existing device/report endpoints currently share a broad role gate, so institution-scoped resource authorization is **not yet implemented**. Until that is complete, this is not suitable for access by unrelated institutions.

Evidence decisions record the authenticated principal subject in an audit field.
A review of evidence still **does not** establish a legally verified owner or National ID.

### Deployment requirements
A vetted institutional identity provider must provide unique, non-reassignable
subjects and secure token issuance with MFA, appropriate key rotation and
revocation, protected operator onboarding, network isolation, TLS, and independent
review of privileged decisions. Restrict the JWKS URL to an approved domain;
apply egress policy to prevent SSRF. Production requires separate tenant and
resource-level permission checks, reviewed schema migrations, and full audit
metadata (request ID, issuer, institution and immutable retention).
