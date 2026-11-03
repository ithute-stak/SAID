# SAID Phase 11 — CEIR / EIR exchange simulator

**Product:** SAID — Powered by Ithute Digital Solutions.

This is a local database-driven simulator for three data-exchange approaches
described by ITU-T Q Supplement 76 (10/2023), supporting the Q.5055 section
11.2 design work. It does NOT implement or claim conformity with the
complete normative interface specification.

## Modes

- `sync_api`: a simulated attempt immediately records a simulated acknowledgement.
- `async_api`: simulated dispatch transitions to awaiting mock acknowledgement.
- `periodic_file`: simulated batch/file exchange also transitions to awaiting
  acknowledgement. No file is generated or imported in this version.

The only available operator identities are `mock_operator_alpha` and
`mock_operator_beta`. No real names, URLs, HTTP clients, SFTP connections,
credentials, IMEI exports or network control messages exist.

## Lifecycle and API

A central authorized operator can enqueue the *current revision* of a CEIR
sandbox proposed status by its simulation ID. The tuple
(operator, simulation, revision, mode) is unique and is idempotent.

- `POST /api/v1/ceir/sandbox/exchange/queue`: enqueue mock delivery.
- `GET /api/v1/ceir/sandbox/exchange/{id}`: inspect.
- `POST /api/v1/ceir/sandbox/exchange/{id}/attempt`: simulate an attempt
  and optional deterministic failure. Failures transition to `retry_pending`
  and may be manually retried. No automated background process runs.
- `POST /api/v1/ceir/sandbox/exchange/{id}/ack`: acknowledge an async or
  periodic simulated exchange.
- `GET /api/v1/ceir/sandbox/exchange/{id}/events`: audit simulation events.
- `GET /api/v1/ceir/sandbox/exchange/reconcile/{mock_operator}`: compare
  acknowledged revisions against the latest simulated source revision.

Every response declares `simulated=true`, `external_transmission=false`
and `network_action_taken=false` where relevant.

## Production blockers

This is NOT an EIR adapter. It cannot synchronize an IMEI or send a block
instruction. A real implementation requires national regulatory authority,
operator contracts, agreed schema/transport, cryptographic message signing,
rate limits, network segregation, acknowledgements, sequencing, retries,
dead-letter queues, batch manifests, replay detection, secrets protection,
operator-specific authorization, retention rules, and operator independent
conformance testing. Authenticated database context must be non-superuser,
NOBYPASSRLS, non-owner, and separate from schema migration privileges.

The mock statuses remain proposed only and never become operational blocked,
tracked or permitted lists.

References:
- https://www.itu.int/rec/T-REC-Q.5055-202603-I/en
- https://www.itu.int/rec/dologin_pub.asp?id=T-REC-Q.Sup76-202310-I%21%21PDF-E&lang=e&type=items
