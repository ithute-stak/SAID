# SAID Phase 20 — Isolated audit-authority sandbox

Phase 20 adds a **separate optional ASGI application** under
`services/audit_authority/app.py`. The main SAID application does NOT import,
mount or call this service. It has no SAID database connection, no operator
transport, and no background task. Only **mock audit checkpoint manifests**
can be signed.

The authority has its own private-key file and isolated receipt SQLite
database. Both must be provisioned separately, outside the repository and
the main SAID runtime. Its Ed25519 raw private key must be exactly 32 bytes
and owner-only readable. **Never share the private key with SAID**.

### Environment, sandbox ONLY

- `SAID_ENVIRONMENT=development` or `test`
- `SAID_AUDIT_SANDBOX_ENABLED=true` (otherwise all issuance is disabled)
- `SAID_AUDIT_AUTHORITY_TOKEN`: independently issued random secret, at least 32 chars
- `SAID_AUDIT_AUTHORITY_KEY_ID`: key ID for the currently provisioned signer
- `SAID_AUDIT_AUTHORITY_KEY_PATH`: absolute file path to owner-only raw Ed25519 secret
- `SAID_AUDIT_AUTHORITY_DB_PATH`: independent, writable SQLite database path

Run in an isolated environment with
`uvicorn services.audit_authority.app:app --host 127.0.0.1 --port 8099`.
Do not publish this sandbox endpoint on an internet-facing listener or
expose it to real telecom operators. No production enablement is supported.

### API

- `POST /v1/mock/receipts`: send canonical `manifest` and `manifest_sha256`.
  A unique manifest is signed once; repeat submission returns the same
  receipt. The bearer-equivalent secret is supplied using the
  `X-Audit-Authority-Token` header, not query parameters.
- `GET /v1/mock/receipts/by-manifest/{manifest_sha256}`: independently
  retrieve an issued receipt by digest.
- `GET /health`: no private secrets or database contents.

Receipt JSON is compatible with SAID Phase 19's offline Ed25519 verifier,
which accepts only configured public keys. It is **not** automatically
transferred back to SAID. Tests exercise both apps independently using
in-process clients and an ephemeral test signing key.

### Trust and risk

The SQLite receipt store prevents UPDATE/DELETE through ordinary SQL
DML triggers, but a database or filesystem administrator can still delete
or rebuild the store. This is **not WORM storage or independently anchored
evidence**. The signing key is loaded by the authority process from a
separate owner-only file, and is never provided to SAID. There is no HSM,
KMS rotation/revocation workflow, trusted timestamping, independent identity
provider, externally accredited auditor, replay-age enforcement at issuance,
or production key custody controls.

A real authority must use separate cloud accounts or infrastructure,
isolated access administration, managed HSM, highly available immutable
storage, signed timestamping, mutual authentication, key rollover/revocation,
and disaster recovery, with organizational and regulatory approval.

No real telecom integration, network blocking, deletion or Q.5055
conformity claim is part of this phase.
