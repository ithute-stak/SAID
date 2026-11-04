# SAID Phase 18 — Assurance preparation (offline simulation)

**SAID — Secure Asset Identity & Detection**, Powered by Ithute Digital Solutions.

## Offline checkpoint manifests

An authorized central auditor may request a deterministic JSON manifest for
a previously recorded local audit checkpoint. The API first verifies the
complete local investigation ledger and then verifies that the selected
checkpoint matches its historical event. The manifest contains only opaque
case/checkpoint identifiers, a sequence, a hash-chain head, checkpoint digest,
and opaque rationale.

The response provides a SHA-256 digest of canonical sorted JSON, allowing a
future, separately approved audit exporter to identify the exact bytes.
**No outbound transfer, cryptographic signature, external timestamp, trust
anchor, auditor receipt, or attestation is implemented.** An ordinary digest
does not authenticate a database server; a privileged database owner may
rebuild local records, therefore this does not establish independent
immutability or legal admissibility.

## Retention plan governance

An independent central supervisor may propose one *plan* per mock
investigation after a completed human review. A distinct central retention
approver with `ceir_retention_approver` permission may approve/reject the
plan. Neither person may be the original investigator or reviewer. An
approver cannot also be the proposal creator.

Plans fail closed when the investigation has an active legal hold, pending
appeal, or appeal returned for further review. A plan is an audited,
one-time decision only. Even `approved_plan_only` has
`execution_enabled=false` and `records_deleted=0`.
**No data deletion, background executor, archival transport, external sync
or key destruction is permitted by this feature.**

The original review-ledger hash chain receives request/decision events.
Actual deletion must not be implemented until legal authorization, hold
release, protected retention dependency checks, independently signed audit
receipts, export verification and recovery plans are established.

## Identity provisioning checklist

Identity provider integration remains a deployment dependency. Use trusted
OIDC access tokens (RS256/ES256) with expected issuer, audience, expiry,
stable unique subject, and centrally managed `said_institution` and
`said_roles` claims. The following are additional permissions requiring
a recorded organizational grant: `ceir_reviewer`, `ceir_appeals_officer`,
`ceir_supervisor`, `ceir_auditor`, and `ceir_retention_approver`.

- Issue identities to *individual* staff members, never shared operator
  accounts, with MFA for privileged access.
- Provision and revoke privileges centrally; approve elevated role
  changes with a separate approver and retain audit of grants.
- Do not let users self-select `said_roles`, `said_institution` or
  `sub`; the API must consume only verified issuer claims.
- Keep schema-owner credentials and production runtime credentials separate.
- Disable development-admin API keys outside testing and development.
- Review permissions and identity uniqueness with independent security tests
  before any real national system is activated.

This phase does **not** claim provider provisioning is live, nor does
it implement a national identity provider, EIR integration, IMEI blocking,
live telecommunications observation, or ITU-T Q.5055 certification.
