"""CI-only real pg_dump / pg_restore drill into a disposable PostgreSQL database.

Never targets a deployed server. Creates a fresh CI target DB and drops only
that DB after verifying a synthetic marker and real migrated constraints.
"""
import hashlib
import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

import psycopg

SRC = "said_ci"
TARGET = "said_restore_ci_phase41"
MARKER_TABLE = "said_phase41_restore_probe"
URL = os.getenv("SAID_DATABASE_URL", "")
assert os.environ.get("SAID_CONCURRENCY_TEST_DB") == "ephemeral-ci-only"
assert os.environ.get("SAID_ENVIRONMENT") == "test"
assert URL == "postgresql+psycopg://said_ci:said_ci_password@localhost:5432/said_ci"
assert os.getenv("PGHOST") == "localhost" and os.getenv("PGPORT") == "5432"
assert os.getenv("PGUSER") == "said_ci" and os.getenv("PGDATABASE") == SRC
assert os.getenv("PGPASSWORD") == "said_ci_password"

def invoke(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=90, env=dict(os.environ)).stdout

def connect(dbname, *, autocommit=False):
    return psycopg.connect(host="localhost", port=5432, dbname=dbname,
                           user="said_ci", password="said_ci_password",
                           autocommit=autocommit, connect_timeout=5)

probe = "PH41_" + uuid.uuid4().hex
created = False
with connect(SRC, autocommit=True) as source:
    # Enforce a fresh destination so pre-existing environments cannot be overwritten.
    assert source.execute("SELECT 1 FROM pg_database WHERE datname=%s",
                          (TARGET,)).fetchone() is None
    try:
        source.execute("CREATE TABLE IF NOT EXISTS " + MARKER_TABLE +
                       " (marker TEXT PRIMARY KEY NOT NULL)")
        source.execute("INSERT INTO " + MARKER_TABLE + " (marker) VALUES (%s)", (probe,))
        with tempfile.TemporaryDirectory(prefix="said_phase41_") as folder:
            backup = Path(folder) / "synthetic.backup"
            invoke("pg_dump", "--host=localhost", "--port=5432", "--username=said_ci",
                   "--dbname=" + SRC, "--format=custom", "--no-owner", "--no-acl",
                   "--file=" + str(backup))
            size = backup.stat().st_size
            assert size > 0
            checksum = hashlib.sha256(backup.read_bytes()).hexdigest()
            source.execute("CREATE DATABASE " + TARGET)
            created = True
            invoke("pg_restore", "--host=localhost", "--port=5432", "--username=said_ci",
                   "--dbname=" + TARGET, "--no-owner", "--no-acl", "--exit-on-error",
                   str(backup))
            with connect(TARGET) as restored:
                marker = restored.execute("SELECT marker FROM " + MARKER_TABLE +
                                          " WHERE marker=%s", (probe,)).fetchone()
                assert marker == (probe,)
                assert restored.execute("SELECT version_num FROM alembic_version").fetchone() == ("0014_assurance",)
                constraints = restored.execute("""
                    SELECT count(*) FROM pg_constraint
                    WHERE contype = 'f' AND conrelid = 'theft_reports'::regclass
                """).fetchone()[0]
                assert constraints >= 1
                assert restored.execute("SELECT count(*) FROM devices").fetchone()[0] >= 0
            print(json.dumps({
                "schema": "said.mock.ephemeral-restore.v1",
                "source": SRC, "destination": TARGET,
                "backup_bytes": size, "backup_sha256": checksum,
                "synthetic_marker_restored": True,
                "migration_revision_verified": True,
                "foreign_keys_verified": True,
                "actual_pg_dump_restore_executed": True,
                "production_data_accessed": False,
                "production_deploy_authorized": False,
            }, sort_keys=True))
    finally:
        if created:
            source.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                           "WHERE datname=%s AND pid<>pg_backend_pid()", (TARGET,))
            source.execute("DROP DATABASE " + TARGET)
        source.execute("DELETE FROM " + MARKER_TABLE + " WHERE marker=%s", (probe,))
