# SAID Phase 22 — Independent Audit Authority deployment preparation

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase adds an **offline** recovery drill, read-only public-key lifecycle
validation, and sample systemd configurations under
`deploy/audit-authority/`. No service is deployed or scheduled by a
repository merge.

## Recovery drill

```sh
python -m audit_authority.cli drill \
  --store /var/lib/said-audit/receipts.db \
  --drill-directory /var/lib/said-audit/drills
```

The drill uses a disposable mode-0700 directory. It invokes SQLite's
consistent backup API, verifies its SHA-256 and database metadata,
restores into a new filename, compares the complete receipt-id/content
digest mapping and counts, and removes temporary copies afterwards.
It does not export signing keys, contact other services, or delete the
original store. The drill's success does **not** prove an off-host backup
exists or that a private-key recovery plan works.

## Key lifecycle readiness

```sh
python -m audit_authority.cli validate-key-registry \
  --store /var/lib/said-audit/receipts.db \
  --registry /private/audit/approved-public-keys.json
```

The registry JSON uses `version=said.mock.audit-public-keys.v1` and
`keys` containing key ID, base64 Ed25519 public key, state
(`staged`, `active`, `retired`, `revoked`), approval subject/reference
and lifecycle timestamps. Validation rejects duplicate IDs, duplicated
public keys, missing timestamps, malformed declarations and any registry
without **exactly one active** signing key. Validation never reads
private keys or rotates a signing key. Operators must separately approve
issuer key rotations and preserve historical verification keys.

## Deployment example

Sample `said-audit-drill.service.example` and
`said-audit-drill.timer.example` illustrate a distinct Unix account,
strict filesystem sandbox, networking disabled, read-only source
and a separate writable drill directory. They are inert reference
files. Do not install on the SAID operational VPS or enable scheduling
before a dedicated independent host, operator approval, and a recovery
exercise in staging. The sample timer uses a weekly cadence as an
**example only**, not an active automation.

## Security gaps

SQLite checksums, receipts and local append-only triggers are not
tamper-resistant external WORM. File/database administrators can
replace storage and manipulate evidence; the supplied CLI is not an
independent audit authority certification. A production architecture
still requires a managed HSM/KMS, protected key revocation registry,
signed timestamp and external receipt checkpoints, off-site encrypted
immutable backups, immutable storage access policies, restore drills,
out-of-band alerts and independent legal/security review.

No real telecom feeds, external transfers, identity checks, blocking
or automated deletion are enabled in this phase.
