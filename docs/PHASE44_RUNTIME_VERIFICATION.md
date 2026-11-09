# SAID Phase 44 — Read-only Staging Runtime Verification

This phase implements a **read-only** inspection tool for containers which have
already been deployed by an independently authorized operator. Nothing in
this phase starts, stops, modifies, or deploys containers.

## Commands

From a machine with a restricted Docker context that points to **approved
staging only**:

```bash
python -m said.staging_runtime_probe --docker-context said-staging --output phase44-runtime-report.json
```

Or evaluate saved, trusted Docker inspect JSON without contacting a host:

```bash
python -m said.staging_runtime_probe --inspect-json /private/evidence/docker-inspect.json
```

The live path executes only `docker --context <context> ps -aq` with the
staging project label and `docker --context <context> inspect`. It makes
no `docker compose up`, login request, carrier API request or mutation.

The scanner requires the two expected services and rejects unhealthy or stopped
containers, published ports, privilege escalation, unapproved mount paths,
missing resource limits, unexpected networks and unpinned image references.

## Limitations and approvals

A healthy report does **not** establish that the Docker network is truly
internal, that external ingress/TLS and identity egress are secure, or that image
provenance is verified. Docker inspect JSON can be fabricated when supplied
offline. Runtime image configuration must be verified against the running image
ID/digest by a separate mechanism; this scanner checks only declared references.

No server has been contacted or tested by the project's GitHub CI; synthetic
fixtures test rejection logic. No real backup restoration, TLS validation,
carrier integration, alert delivery, penetration testing or live recovery drill
is included. No staging or production deployment authorization is granted.

A future controlled exercise must independently confirm host/network isolation,
identity transport, evidence authenticity, backup recovery, and incident response
before any deployment readiness decision.
