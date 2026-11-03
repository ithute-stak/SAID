"""PostgreSQL row-level security for the institution-scoped SAID records.

Revision ID: 0004_rls
Revises: 0003_institution

SQLite is only used for local unit tests; PostgreSQL policies are the security
boundary to test before enabling multi-institution use.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_rls"
down_revision = "0003_institution"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("audit_events", sa.Column("institution_id", sa.String(120), nullable=True))
    op.create_index("ix_audit_events_institution_id", "audit_events", ["institution_id"])
    if op.get_bind().dialect.name != "postgresql":
        return
    # The application role must never have BYPASSRLS or superuser privileges.
    for name in ("devices", "theft_reports", "ownership_claims", "audit_events"):
        op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")

    device_scope = """(
        current_setting('said.central', true) = 'true'
        OR (institution_id IS NOT NULL
            AND institution_id = nullif(current_setting('said.institution', true), ''))
    )"""
    child_scope = """(
        EXISTS (
            SELECT 1 FROM devices d
             WHERE d.id = device_id
        )
    )"""
    # The nested device SELECT is itself checked by the devices policy.
    # Consequently an unscoped or differently-scoped child has no visibility.
    for name, expr in (
        ("devices", device_scope),
        ("theft_reports", child_scope),
        ("ownership_claims", child_scope),
        ("audit_events", device_scope),
    ):
        op.execute(f"CREATE POLICY {name}_institution_policy ON {name} "
                   f"FOR ALL USING {expr} WITH CHECK {expr}")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for name in ("devices", "theft_reports", "ownership_claims", "audit_events"):
            op.execute(f"DROP POLICY IF EXISTS {name}_institution_policy ON {name}")
            op.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {name} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_audit_events_institution_id", table_name="audit_events")
    op.drop_column("audit_events", "institution_id")
