# Phase 19 — Separate public-key audit verifier prototype

**SAID — Powered by Ithute Digital Solutions.**

The SAID application now includes an **offline receipt verification interface**
at `POST /api/v1/ceir/sandbox/verification/receipts/verify`.
It validates a detached Ed25519 signature over canonical JSON:
`version`, `key_id`, `manifest`, `manifest_sha256`, `issued_at`.

A receipt may be generated and signed by an **independently run, approved
external audit authority** in future. The SAID server deliberately contains
no signing function or audit private keys. This prototype has no
automatic external receipt issuer, storage, export or callbacks.

## Trust configuration

`SAID_AUDIT_PUBLIC_KEYS_JSON` is a JSON dictionary mapping trusted key IDs
to base64-encoded raw 32-byte Ed25519 **public** keys. This value must be
managed outside the app by a trusted deployment authority. An absent, malformed
or empty trust set fails closed (HTTP 503). Test code generates a temporary
key in memory, never using production keys.

Signature validation performs pinned-key lookup, canonical payload and
manifest SHA-256 comparison, Ed25519 verification, and rejects receipts
with naive/future or older-than-365-day timestamps. That window is a
**prototype replay-age bound**, not a full replay-proof timestamp service.

## Claims and limitations

A valid signature proves the holder of a private key corresponding to a
locally trusted public key signed the supplied document. It **does not**
prove the signer is an accredited external auditor, the document was anchored
outside SAID, or the receipt matches a currently valid SAID case.
The response therefore always declares:
`signature_only=true`, `local_checkpoint_compared=false`,
`externally_anchored=false`, `simulated=true`,
`network_action_taken=false`.

A real independent verifier should run in separate operational and
administrative trust domains, with a hardened audit service, external
tamper-resistant receipts, verified operator onboarding, controlled
key rotation/revocation, accurate timestamping, persistence and
replay protection, legal retention policy, and independent security
and conformity testing.

No mobile network access, real IMEI blocking, SIM analysis, national
identity verification or ITU certification is performed here.
