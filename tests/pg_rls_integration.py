"""Real PostgreSQL RLS integration checks using a non-owner, NOBYPASSRLS role.

Runs only against an ephemeral PostgreSQL CI service. Do not run on real data.
"""
import os
import uuid

import psycopg
from sqlalchemy import create_engine, inspect, text

url = os.environ["SAID_DATABASE_URL"]
admin = create_engine(url)
with admin.begin() as conn:
    conn.execute(text(
        "CREATE ROLE said_runtime_ci LOGIN PASSWORD 'temporary-ci-only' NOSUPERUSER NOBYPASSRLS"
    ))
    conn.execute(text("GRANT USAGE ON SCHEMA public TO said_runtime_ci"))
    for table in ("devices", "theft_reports", "ownership_claims", "audit_events"):
        conn.execute(text(
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO said_runtime_ci"
        ))
        info = conn.execute(text(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid = to_regclass(:name)"
        ), {"name": table}).one()
        assert info == (True, True), (table, info)

dsn = "host=localhost port=5432 dbname=said_ci user=said_runtime_ci password=temporary-ci-only"
device_a = str(uuid.uuid4())
device_b = str(uuid.uuid4())
report_a = str(uuid.uuid4())
claim_a = str(uuid.uuid4())
audit_a = str(uuid.uuid4())

def set_tenant(conn, institution: str, central: bool = False):
    conn.execute("SELECT set_config('said.institution', %s, true)", (institution,))
    conn.execute("SELECT set_config('said.central', %s, true)",
                 ("true" if central else "false",))

with psycopg.connect(dsn) as conn:
    with conn.transaction():
        # No context fails closed even for a valid table read.
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0

    with conn.transaction():
        set_tenant(conn, "operator-a")
        conn.execute(
            """INSERT INTO devices
            (id, imei, owner_reference, institution_id, make, model,
             verification_status, created_at)
            VALUES (%s, %s, 'owner-a', 'operator-a', 'Test', 'Model',
                    'unverified', now())""",
            (device_a, "490154203237518"),
        )
        conn.execute(
            """INSERT INTO theft_reports
            (id, device_id, incident_reference, status, created_at)
            VALUES (%s, %s, 'test-report', 'reported_pending_review', now())""",
            (report_a, device_a),
        )
        conn.execute(
            """INSERT INTO ownership_claims
            (id, device_id, applicant_reference, evidence_reference, status, created_at)
            VALUES (%s, %s, 'applicant', 'evidence', 'pending_review', now())""",
            (claim_a, device_a),
        )
        conn.execute(
            """INSERT INTO audit_events
            (id, action, entity_type, entity_id, institution_id, recorded_at)
            VALUES (%s, 'device.registered_unverified', 'device', %s, 'operator-a', now())""",
            (audit_a, device_a),
        )
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 1

    with conn.transaction():
        # Transaction-local GUCs must not survive across requests/connections.
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM theft_reports").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM ownership_claims").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0

    with conn.transaction():
        set_tenant(conn, "operator-b")
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM theft_reports").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM ownership_claims").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0
        assert conn.execute("UPDATE devices SET make='stolen' WHERE id=%s",
                            (device_a,)).rowcount == 0

    # Attempting a cross-tenant insert is rejected by WITH CHECK.
    try:
        with conn.transaction():
            set_tenant(conn, "operator-b")
            conn.execute(
                """INSERT INTO devices
                (id, imei, owner_reference, institution_id, make, model,
                 verification_status, created_at)
                VALUES (%s, %s, 'bad', 'operator-a', 'Test', 'Model',
                        'unverified', now())""",
                (device_b, "490154203237526"),
            )
    except psycopg.errors.InsufficientPrivilege:
        pass
    else:
        raise AssertionError("Cross-tenant INSERT was not denied")

    with conn.transaction():
        set_tenant(conn, "operator-a")
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM theft_reports").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM ownership_claims").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 1

print("PostgreSQL RLS isolation tests passed")
