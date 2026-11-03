"""Consent-only ownership link intents with PostgreSQL citizen-subject isolation.

Revision ID: 0006_link_intents
Revises: 0005_citizen
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_link_intents"
down_revision = "0005_citizen"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "citizen_link_intents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("citizen_subject", sa.String(200), nullable=False),
        sa.Column("inquiry_id", sa.String(36), sa.ForeignKey("citizen_requests.id"), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("consent_version", sa.String(24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("inquiry_id", name="uq_link_intent_inquiry"),
    )
    op.create_index("ix_citizen_link_intents_citizen_subject", "citizen_link_intents", ["citizen_subject"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE citizen_link_intents ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE citizen_link_intents FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY citizen_link_intents_subject_policy ON citizen_link_intents
            FOR ALL
            USING (
                citizen_subject = nullif(current_setting('said.subject', true), '')
                AND current_setting('said.institution', true) = 'citizens'
                AND EXISTS (
                    SELECT 1 FROM citizen_requests r
                    WHERE r.id = inquiry_id AND r.citizen_subject = citizen_subject
                )
            )
            WITH CHECK (
                citizen_subject = nullif(current_setting('said.subject', true), '')
                AND current_setting('said.institution', true) = 'citizens'
                AND EXISTS (
                    SELECT 1 FROM citizen_requests r
                    WHERE r.id = inquiry_id AND r.citizen_subject = citizen_subject
                          AND r.category = 'ownership_inquiry'
                )
            )""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS citizen_link_intents_subject_policy ON citizen_link_intents")
        op.execute("ALTER TABLE citizen_link_intents NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE citizen_link_intents DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_citizen_link_intents_citizen_subject", table_name="citizen_link_intents")
    op.drop_table("citizen_link_intents")
