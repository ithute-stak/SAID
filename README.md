# SAID — Secure Asset Identity & Detection

**Protecting Devices. Verifying Ownership.**

SAID is an Ithute Digital Solutions product for phone ownership registration, IMEI validation, lost/stolen device reports and future authorized network identity cooperation.

> Development status: foundational prototype with API-level institution isolation. NOT a national CEIR, identity authority or operational network blocking system. LCA, Vodacom and Econet are prospective partners only.

## Principles
- Never modify device operating systems or require firmware changes.
- National ID verification and network subscriber information require separately authorized integrations; never assume a user-provided ID is verified.
- A changed IMEI cannot be inferred from an old IMEI alone.
- No live operator block/unblock functionality is enabled.
- Minimize sensitive personal information and maintain case audit events.

## Local development

```bash
cp .env.example .env
# Set a long random SAID_ADMIN_API_KEY in .env (never commit it)
docker compose build
docker compose run --rm api alembic upgrade head
docker compose up -d
```

SAID Protect consent-only ownership-link groundwork: see `docs/OWNERSHIP_LINKING_PHASE9.md`. No verified device ownership or device entitlement is issued.\n\nSAID Protect limited citizen inquiry prototype: http://localhost:8000/protect/ (requires a vetted citizen identity-provider bearer token; no ownership verification).\n\nSAID Control internal prototype: http://localhost:8000/console/ (requires institutional bearer token; no anonymous citizen access).\n\nAPI docs: http://localhost:8000/docs (development-only X-Admin-Key or institutional JWT as configured).

CEIR sandbox aligned to the published Q.5055 function areas (simulation only): see `docs/Q5055_TRACEABILITY.md`. No EIR network blocking or synchronization.\n\nSimulated CEIR–EIR sync and acknowledgements: see `docs/CEIR_EIR_SIMULATOR.md` (no real operator connection or network actions).\n\nCEIR data-quality and investigation sandbox (no automatic status changes): see `docs/CEIR_QUALITY.md`.\n\nSAID simulated independent appeals and supervisor workflow: see `docs/INTELLIGENCE_APPEALS_PHASE16.md`.\n\nSAID Intelligence governance: distinct human reviewer with `ceir_reviewer` role, hash-chained review audit and retention dry-run: see `docs/INTELLIGENCE_SECURITY_PHASE15.md`.\n\nSAID Intelligence prototype review dashboard: http://localhost:8000/intelligence/ (restricted central-token data operations).\n\nSAID Intelligence simulated evidence provenance, explainable assessments and review queue: see `docs/SAID_INTELLIGENCE.md`.\n\nSee `docs/SAID_INTELLIGENCE.md`, `docs/CEIR_QUALITY.md`, `docs/CEIR_EIR_SIMULATOR.md`, `docs/Q5055_TRACEABILITY.md`, `docs/OWNERSHIP_LINKING_PHASE9.md`, `docs/SAID_PROTECT.md`, `docs/INSTITUTION_ISOLATION.md`, `docs/INSTITUTIONAL_ACCESS.md`, `docs/ARCHITECTURE.md`, `docs/DATABASE_MIGRATIONS.md` and `docs/ROADMAP.md`.
