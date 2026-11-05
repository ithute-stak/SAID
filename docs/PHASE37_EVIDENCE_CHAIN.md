# SAID Phase 37 — Release Evidence Digest Chain

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

The new `said.evidence_chain` module verifies the producer checksums of five
already generated reports and a fixed, domain-separated ordered hash chain:
**CI → PR review → ruleset → reviewer team → staging dossier**.

Each report must be a JSON object with the expected schema identifier and
exact same 40-character commit SHA. Its original `report_sha256` or `sha256`
is recomputed with the same canonical JSON serializer used by the current
SAID reporting code (sorted keys, compact separators, UTF-8 JSON text,
excluding the digest field itself). The envelope must carry the report digest,
prior chain digest and computed chain digest. The final root must match.

The verifier also rejects failed check flags, reported issues and unexpected
claims that staging, production or telecom operations were authorized.

Example invocation, after an envelope has been assembled:

```sh
python -m said.evidence_chain --chain /private/release/evidence-chain.json
```

An envelope has schema `said.mock.release-chain.v1`, a `commit_sha`,
five ordered `entries` containing `kind`, `report`, `report_digest`,
`previous_digest`, `chain_digest`, and a `root_digest`.
The pure `build_chain(commit_sha, reports)` helper creates an untrusted
candidate envelope for offline verification; it does not sign anything.

**Critical authenticity limitation:** The chain hashes prove *internal
consistency*, not independent provenance. Anyone able to replace the
entire bundle can recalculate every digest and produce a plausible chain.
No external timestamp anchor, KMS/HSM signature, trusted witness, detached
signer or independent infrastructure attestation is verified by this phase.
The report explicitly sets `external_anchor_verified=false`,
`cryptographic_signature_verified=false`, and
`report_origin_independently_authenticated=false`.

The code uses no production network or operator integrations and cannot
approve staging/production, enable telecom operations or block a device.
The next required step is a **separate trust domain** that signs/anchors the
root digest with independent access controls and verification of evidence
origin against the relevant GitHub and host sources.
