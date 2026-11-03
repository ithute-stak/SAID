# Phase 12 — SAID CEIR simulated data quality

**SAID, Powered by Ithute Digital Solutions.**

The CEIR data-quality sandbox accepts only hypothetical observations from
`mock_operator_alpha` and `mock_operator_beta`. Each observation contains
a 15-digit IMEI (validated with Luhn) and an opaque mock source reference.
The IMEI is never returned by API responses and is not stored in the
observation table. A keyed HMAC-SHA256 token allows offline equality checks.
Configure `SAID_CEIR_HMAC_KEY` using a secret at least 32 characters long.

Signals:
- Repeated mock observations with the same IMEI token.
- The same IMEI token seen in more than one hypothetical source.
- Clean sample without a repeat observation.

**None of these demonstrates that there are two physical phones or that an
IMEI has been modified.** Multiple observations may be entirely legitimate.
The algorithm cannot infer a changed IMEI from the former IMEI alone.

The central-only API can open a human investigation and record a single
decision. Decisions are limited to `needs_investigation`,
`insufficient_evidence` or `closed_false_positive`. This deliberately
does not set a CEIR status or create an EIR operator instruction.

Production blockers: verified data provenance, lawful source authorization,
field-level encryption/pseudonymization strategy and key rotation, institution
and investigator segregation of duties, immutable audits, expiry and deletion,
false-positive assessment and appeal process, data-quality metrics and
real consent/legal-basis review. HMAC tokens of a 15-digit numeric identifier
remain sensitive pseudonymous data, not anonymous data. Never reuse this
sandbox for real subscriber monitoring or network decisions.
