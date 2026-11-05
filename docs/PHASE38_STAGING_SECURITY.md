# SAID Phase 38 — Offline Staging Security Control Gate

SAID is a controlled prototype, powered by Ithute Digital Solutions.

Phase 38 adds a **declarative, fail-closed staging security checklist**, bound
to the exact commit SHA and Phase 37 evidence chain root. It checks the
presence and declared verification state of fourteen controls:
- isolated staging environment and synthetic data;
- private database, restricted DB role and TLS ingress;
- external secrets management, restricted administrator access and limits;
- centralized security logs, encrypted backups and demonstrated restoration;
- incident-response runbook;
- mock-only CEIR paths and denial of telecom-network egress.

Run: `python -m said.staging_security --snapshot /private/staging/snapshot.json`.

The JSON input uses `schema: said.mock.staging-security-input.v1`,
`commit_sha`, `evidence_chain_root`,
`evidence_chain_integrity_consistent`, a host reference, and a `controls`
list with unique `name`, `state` (`verified`, `failed`, `not_checked`)
and `evidence_reference` for every required control.

A complete report means **only that operator-supplied declarations are
internally consistent**. This tool performs **no host access**, no live Docker
inspection, no cloud policy attestation, no external signature verification,
and no external anchoring of the release-chain root. Even all `verified`
flags cannot grant staging or production deployment permission. The output
always sets `staging_deploy_authorized=false`,
`production_deploy_authorized=false`, and
`telecom_operations_enabled=false`.

This staging checklist must be validated on a genuinely isolated host with
independent evidence and human release approval before any deployment.
No telecommunications operators are integrated or contacted by this phase.
