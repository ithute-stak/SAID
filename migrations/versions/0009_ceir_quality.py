"""Central-only simulated IMEI observations and human review.

Revision ID: 0009_ceir_quality
Revises: 0008_mock_exchange
"""
from alembic import op
import sqlalchemy as sa

revision = "0009_ceir_quality"
down_revision = "0008_mock_exchange"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("ceir_mock_observations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("source_code", sa.String(40), nullable=False),
        sa.Column("reference", sa.String(120), nullable=False),
        sa.Column("imei_token", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source_code", "reference", name="uq_ceir_mock_observation_reference"))
    op.create_index("ix_ceir_mock_observations_imei_token", "ceir_mock_observations", ["imei_token"])
    op.create_table("ceir_mock_investigations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("observation_id", sa.String(36), sa.ForeignKey("ceir_mock_observations.id"), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("reviewer_reference", sa.String(200), nullable=True),
        sa.Column("decision_reference", sa.String(120), nullable=True),
        sa.UniqueConstraint("observation_id", name="uq_ceir_mock_investigation_observation"))
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_observations", "ceir_mock_investigations"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"""CREATE POLICY {table}_central_only ON {table}
                FOR ALL USING (current_setting('said.central', true) = 'true')
                WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_investigations", "ceir_mock_observations"):
            op.execute(f"DROP POLICY IF EXISTS {table}_central_only ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_table("ceir_mock_investigations")
    op.drop_index("ix_ceir_mock_observations_imei_token", table_name="ceir_mock_observations")
    op.drop_table("ceir_mock_observations")
