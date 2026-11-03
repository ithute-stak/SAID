"""Citizen subject-scoped intake, not a verified ownership registry.

Revision ID: 0005_citizen
Revises: 0004_rls
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_citizen"
down_revision = "0004_rls"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "citizen_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("citizen_subject", sa.String(200), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("device_reference", sa.String(120), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_citizen_requests_citizen_subject", "citizen_requests",
                    ["citizen_subject"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE citizen_requests ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE citizen_requests FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY citizen_request_subject_policy ON citizen_requests
            FOR ALL
            USING (
                citizen_subject = nullif(current_setting('said.subject', true), '')
                AND current_setting('said.institution', true) = 'citizens'
            )
            WITH CHECK (
                citizen_subject = nullif(current_setting('said.subject', true), '')
                AND current_setting('said.institution', true) = 'citizens'
            )""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS citizen_request_subject_policy ON citizen_requests")
        op.execute("ALTER TABLE citizen_requests NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE citizen_requests DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_citizen_requests_citizen_subject", table_name="citizen_requests")
    op.drop_table("citizen_requests")
