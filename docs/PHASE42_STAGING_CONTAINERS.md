# SAID Phase 42 — Isolated Staging Container Policy

This phase adds a **non-deployed**, internal-only Compose template (`compose.staging.yml`)
and an offline rendered-configuration validator. It is intentionally *not* an
internet-reachable staging installation. Do not use the development `compose.yaml`
or production credentials for this template.

## What the template enforces

- A private, Docker `internal: true` network connecting only the API and PostgreSQL;
  no `ports:` mapping, external networks, reverse proxy or telecommunications route.
- A non-root, read-only API container with dropped capabilities, no new privileges,
  restricted processes/CPU/memory, and a small temporary filesystem.
- A separate PostgreSQL volume; no API database migrations at startup.
- Host-managed Docker secret file for the database password, mounted into both
  services as `/run/secrets/pg_password`. No credential embedded in the Compose file.
- Required SHA-256-pinned container-image references supplied out of band. The image
  digest is a *configuration requirement*, not proof of image provenance.
- `SAID_ENVIRONMENT=staging`, disabled legacy admin-key auth, required HTTPS-form
  OIDC issuer and JWKS endpoint, and fail-closed startup checks.
- Local container health probes, non-automatic restart, security-resource limits.

## Config-only validation in CI

GitHub Actions supplies disposable dummy values, runs
`docker compose -f compose.staging.yml config --format json` and passes its
output to `python -m said.staging_compose_policy --config-json <file>`.
This does **not** run `docker compose up`, pull images or contact a staging host.

The `said.staging_entrypoint` module reads the mounted password and constructs
the database connection at startup. Missing identity settings, insecure HTTP OIDC
URLs, legacy admin keys, invalid identifiers or a missing/weak secret prevent
the API from starting. The command does not modify the database.

## Before any actual staging deployment

**No public HTTPS endpoint or OIDC key refresh works automatically from this
private-only template.** Because the network is internal, a remote OIDC JWKS
endpoint cannot be reached without a separately approved and tightly restricted
identity-egress design. This design is intentionally left unresolved to avoid
implicitly granting carrier/internet access. A trusted ingress/TLS terminator,
audited ID-provider transport, actual image signing/provenance verification,
container-runtime compatibility and independent host hardening are prerequisites.

A deployment operator must independently verify all controls and obtain written
authorization for the isolated staging environment. **No actual deployment,
production capability, mobile-network integration or national CEIR authorization
is provided by Phase 42.**
