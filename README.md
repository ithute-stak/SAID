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

SAID Control internal prototype: http://localhost:8000/console/ (requires institutional bearer token; no anonymous citizen access).\n\nAPI docs: http://localhost:8000/docs (development-only X-Admin-Key or institutional JWT as configured).

See `docs/INSTITUTION_ISOLATION.md`, `docs/INSTITUTIONAL_ACCESS.md`, `docs/ARCHITECTURE.md`, `docs/DATABASE_MIGRATIONS.md` and `docs/ROADMAP.md`.
