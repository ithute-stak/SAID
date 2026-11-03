# Database schema management — SAID Phase 3

SAID uses versioned Alembic migrations. An application startup **must not** silently create or update tables.

## New development database
1. Configure `SAID_ADMIN_API_KEY` and `SAID_DATABASE_URL` in a local environment (never commit them).
2. Run `alembic upgrade head` before launching API workers.
3. Run `alembic current` to inspect the applied version.
4. Run `pytest` for the separately isolated test database.

With Docker Compose:
```sh
cp .env.example .env
# Replace placeholder secret and use non-default database credentials.
docker compose build
docker compose run --rm api alembic upgrade head
docker compose up -d
```

## Existing databases warning
Do **not** apply the initial migration to an existing Phase 1/2 database with tables already created by `create_all`. First back up, inspect, compare the actual schema against the versioned schema, and explicitly baseline with `alembic stamp 0001_initial` *only* if the schemas match. `stamp` does not create or validate database objects and should not be applied blindly.

## Deployment prerequisites
Use separate credentials and managed secrets, least privilege, offsite backups and restore drills, TLS, an approved retention policy and operator/legal governance. Never run destructive `downgrade` on a database containing real device or ownership data.
