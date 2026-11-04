# SAID Phase 25 — Offline Host Evidence Assessment

SAID — Secure Asset Identity & Detection · Powered by Ithute Digital Solutions.

This phase prepares operator-supplied systemd effective-property snapshots,
separation-of-duties checks, and deterministic evidence digests for
independent review. No SSH, host inspection agent, network calls, remote
execution, certificate issuance, or actual production deployment is enabled.

## Offline assessment command

```sh
python -m audit_authority.cli assess-host \
  --snapshot /private/audit/host-snapshot.json
```

The host snapshot must be collected out of band by an independently
authorized operator. It contains UTC-aware collection time, a pseudonymous
host identifier, specific effective systemd properties, distinct accounts
for service, database owner, signing-key custody, audit review and deployment
operations, and boolean operator attestations about independent hosting,
HSM/KMS key custody and immutable off-site backup verification.

Any missing, stale, or conflicting control marks the result as failed.
The CLI emits a reproducible SHA-256 evidence digest, **not a digital
signature**. In particular, an operator can self-report inaccurate or forged
values, so a passing local assessment does not prove the host is configured
correctly, establish independent compliance, or grant deployment approval.

Phase 25's next operational dependency is a supervised real-host
inspection, performed by a separate governance team and supported by
independently signed evidence and key approval. No telecom data, IMEI
blocking, or automated audit transmission is authorized.
