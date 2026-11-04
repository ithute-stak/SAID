"""Offline assurance: audit export preparation and retention plan approvals.

Revision ID: 0014_assurance
Revises: 0013_oversight
"""
from alembic import op
import sqlalchemy as sa

revision = "0014_assurance"
down_revision = "0013_oversight"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ceir_mock_retention_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_investigations.id"), nullable=False),
        sa.Column("rationale_reference", sa.String(120), nullable=False),
        sa.Column("requested_by", sa.String(200), nullable=False),
        sa.Column("approved_by", sa.String(200), nullable=True),
        sa.Column("approval_reference", sa.String(120), nullable=True),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("investigation_id", name="uq_ceir_retention_approval_case"),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE ceir_mock_retention_approvals ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_retention_approvals FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY ceir_mock_retention_approvals_central_only
            ON ceir_mock_retention_approvals
            FOR ALL USING (current_setting('said.central', true) = 'true')
            WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("""DROP POLICY IF EXISTS ceir_mock_retention_approvals_central_only
            ON ceir_mock_retention_approvals""")
        op.execute("ALTER TABLE ceir_mock_retention_approvals NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_retention_approvals DISABLE ROW LEVEL SECURITY")
    op.drop_table("ceir_mock_retention_approvals")
