# SAID Phase 21 — Offline Audit Authority recovery hardening

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase adds integrity inspection, backup, verification and **restore only
to a nonexistent path** for the independent, mock-only audit-authority SQLite
database. No backup or restore API is mounted on the SAID FastAPI application.

## Commands

Run under a separate operating-system account, using a private filesystem
that is not mounted into SAID's operational containers:

```sh
python -m audit_authority.cli inspect --store /private/audit/receipts.db
python -m audit_authority.cli backup --store /private/audit/receipts.db --backup-path /private/audit-backup/receipts-2026-11.db
python -m audit_authority.cli verify-backup --store /private/audit/receipts.db --backup-path /private/audit-backup/receipts-2026-11.db --expected-sha256 YOUR_APPROVED_DIGEST
python -m audit_authority.cli restore --store /private/audit/recovered-new.db --backup-path /private/audit-backup/receipts-2026-11.db --expected-sha256 YOUR_APPROVED_DIGEST
```

The source database is backed up using SQLite's native backup API; the
backup and restore are created with restrictive permissions. Restores refuse
to overwrite existing targets, and verification checks SQLite integrity,
append-only triggers, manifest and receipt hashes, and a caller-supplied
SHA-256 digest. Copy the expected digest to separately managed trusted
storage; **a SHA-256 checksum is not an authenticated signature**.

### Recovery exclusions

The backup does not include private key material, passphrases or external
trusted-public-key configuration. A restored database **must not be
used to issue new receipts** before operators restore the applicable
private-key custody and verify historical receipts against the approved
independent public-key registry.

### Key-rotation preparation

Maintain an independently approved key register with key ID, public key,
activated/deactivated dates, signed authorization and key revocation
status. Each issuance identifies its key ID. Preserve historical public
keys for verification; never silently overwrite an existing key ID with
another public key. A future production HSM/KMS integration must support
non-exportable private signing keys, audit logs, revocation and rollback-safe
rotation. **Automated rotation and key replacement are not implemented.**

### Deployment boundary

Run the authority from a separate host or highly restricted OS account,
disable outbound network access where possible and isolate audit volumes.
Keep encrypted private key files, passphrases and signed receipts outside
the SAID app and its database. Use offline runbook-approved manifest inputs.

This is not WORM storage: an administrator with filesystem or database
schema authority can replace the entire SQLite store. Production use
requires immutable off-host replicas, externally signed checkpoints,
hardware-backed key custody, restore drills and independent security review.
No operator integration or IMEI blocking is enabled.
