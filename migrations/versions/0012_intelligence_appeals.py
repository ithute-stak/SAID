"""Appeals with central-only RLS. Revision ID: 0012_appeals.

Revises: 0011_governance
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_appeals"
down_revision = "0011_governance"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ceir_mock_appeals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_investigations.id"), nullable=False),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("reason_reference", sa.String(120), nullable=False),
        sa.Column("submitted_by", sa.String(200), nullable=False),
        sa.Column("reviewed_by", sa.String(200), nullable=True),
        sa.Column("decision_reference", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("investigation_id", name="uq_ceir_appeal_case"),
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE ceir_mock_appeals ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_appeals FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY ceir_mock_appeals_central_only ON ceir_mock_appeals
            FOR ALL USING (current_setting('said.central', true) = 'true')
            WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS ceir_mock_appeals_central_only ON ceir_mock_appeals")
        op.execute("ALTER TABLE ceir_mock_appeals NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_appeals DISABLE ROW LEVEL SECURITY")
    op.drop_table("ceir_mock_appeals")
