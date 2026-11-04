# SAID Phase 20 — Separate offline audit-authority prototype

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

The `audit_authority/` package is a **separately operated, command-line
prototype**, not a service mounted inside SAID FastAPI. It accepts only
hypothetical Phase 18 checkpoint manifests, signs deterministic canonical
JSON with Ed25519 and stores receipts in a distinct SQLite database.

## Operational separation

- Run the CLI as a different OS service user, ideally a different host.
- Use a separate filesystem and protected SQLite database for receipts.
- Supply an *encrypted* PKCS8 Ed25519 private key from a protected key file
  with mode 0600; the passphrase is read from
  `AUDIT_AUTHORITY_PASSPHRASE`, never a command argument.
- **Do not mount private signing keys or audit databases into SAID FastAPI,
  its Docker container, or its application database.**
- Provision SAID's verifier with **only** a pinned, independently approved
  Ed25519 public key via `SAID_AUDIT_PUBLIC_KEYS_JSON`.
- Manifests must be transferred to the separate authority by an approved
  offline, controlled process; no automatic network transport is included.

The CLI supports `issue`, `get`, and `reconcile`, e.g.:

```sh
python -m audit_authority.cli issue \
  --store /private/audit/receipts.db \
  --key-file /private/audit/signing.pem \
  --key-id independent-auditor-v1 \
  --manifest /private/audit/checkpoint.json
```

The `issue` command returns a signed receipt compatible with SAID's
Phase 19 verification contract. The `reconcile` command consumes a JSON
list of checkpoint manifest objects and reports missing, matching or
mismatched locally stored receipt digests. A reported
`digest_match_only` does **not** recheck the signing key; use
signature verification separately.

## Key rotation and limitations

The key ID is stored with each immutable receipt. Replacing an issuer's
key should allocate a new ID and preserve old public keys for historical
signature checks, subject to an independently governed revocation policy.
This prototype does not automate key rotation, HSM/KMS integration,
certificate enrollment, immutable external storage, audit delivery,
replay-protected issuance, timestamp attestation or a public transparency log.

SQLite triggers block normal UPDATE/DELETE operations and receipts are
content-hashed, but a filesystem administrator can alter the database
or replace it. This is **not WORM storage or independent legally certified
anchoring**. Independent governance and security reviews remain mandatory.

This component has no operator network access, national CEIR controls,
real subscriber data, external transmissions, identity integration,
automatic IMEI blocking or data deletion.
