# SAID CEIR — ITU-T Q.5055 (03/2026) traceability baseline

**Status:** Design mapping and central-only sandbox. NOT certification, compliance,
operational CEIR or operator EIR synchronization.

Official sources:
- ITU-T Q.5055 (03/2026), approved 11 March 2026:
  https://www.itu.int/rec/T-REC-Q.5055-202603-I/en
- ITU published table of contents:
  https://www.itu.int/dms_pubrec/itu-t/rec/q/T-REC-Q.5055-202603-I!!TOC-HTM-E.htm
- ITU-T Q Supplement 76 (10/2023):
  https://www.itu.int/ITU-T/recommendations/rec.aspx?id=15780&lang=en

| Q.5055 published section | SAID implementation | State |
|---|---|---|
| 10.1 Registration | `said/main.py` device registration | Prototype, not CEIR ingestion |
| 10.2 Verification | IMEI checksum, consent-only review | Partial |
| 10.3 Blocking | Sandbox `proposed_blocked` label | **Simulation only**, no blocking |
| 10.4 Tracking/tracing | Inquiry/report intake | No carrier observation capability |
| 10.5 Regulatory compliance | Planned regulator adapter | Not implemented |
| 11.1 Data storage | PostgreSQL + RLS, simulated entries and events | Prototype |
| 11.2 IMEI data/status synchronization | Planned outbound adapter interface | Not implemented |
| 11.3 IMEI data management | Existing registry and sandbox event history | Partial |
| 11.4 Device status management | Central-only proposed-status workflow | Simulation only |
| 11.5 Duplicate/counterfeit detection | Planned anomaly engine | Not implemented |
| 11.6 IMEI verification/query processing | IMEI checksum and admin lookup | Partial |
| 11.7 User/access management | JWT and institutional roles | Prototype |
| 11.8 Notifications | Planned service | Not implemented |
| 11.9 Data quality/validation | IMEI checksum; constrained enums | Partial |

### Guardrails
- `ceir_simulations` and `ceir_simulation_events` are NOT operator
  equipment identity registers, blocklists, EIR commands or enforceable statuses.
- No SAID API exports any status instructions to LCA, Vodacom, Econet,
  GSMA, or any third party.
- Simulated proposed statuses require a central SAID admin,
  and optimistic revision to avoid accidental overwrites.
- PostgreSQL row-level security enforces central-only sandbox rows. The
  database runtime account must be non-owner and NOBYPASSRLS.
- Actual CEIR/EIR data exchange (sync API, async API, file exchange)
  must be separately designed, reviewed and authorized under national policy.
- No assertion of ITU conformity until a full clause-by-clause assessment,
  protocol test program, and review of the complete normative text.

Future work: policy approvals; carrier sandbox schemas; data minimization,
change signatures, tamper-evident audit, quality checks, simulator contracts,
reconciliation, rate limiting, and non-network sanctions/appeal governance.
