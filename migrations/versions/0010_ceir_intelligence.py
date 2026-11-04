"""CEIR mock provenance and append-only assessment snapshots.

Revision ID: 0010_intelligence
Revises: 0009_ceir_quality
"""
from alembic import op
import sqlalchemy as sa

revision = "0010_intelligence"
down_revision = "0009_ceir_quality"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ceir_mock_provenance",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("observation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_observations.id"), nullable=False),
        sa.Column("source_code", sa.String(40), nullable=False),
        sa.Column("provenance_kind", sa.String(32), nullable=False),
        sa.Column("evidence_reference", sa.String(120), nullable=False),
        sa.Column("recorded_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("observation_id", name="uq_ceir_mock_provenance_observation"),
    )
    op.create_table(
        "ceir_mock_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("observation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_observations.id"), nullable=False),
        sa.Column("distinct_sources", sa.Integer(), nullable=False),
        sa.Column("same_imei_count", sa.Integer(), nullable=False),
        sa.Column("provenance_count", sa.Integer(), nullable=False),
        sa.Column("conclusion", sa.String(40), nullable=False),
        sa.Column("assessed_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ceir_mock_assessments_observation_id",
                    "ceir_mock_assessments", ["observation_id"])
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_provenance", "ceir_mock_assessments"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"""CREATE POLICY {table}_central_only ON {table}
                FOR ALL USING (current_setting('said.central', true) = 'true')
                WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_assessments", "ceir_mock_provenance"):
            op.execute(f"DROP POLICY IF EXISTS {table}_central_only ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ceir_mock_assessments_observation_id",
                  table_name="ceir_mock_assessments")
    op.drop_table("ceir_mock_assessments")
    op.drop_table("ceir_mock_provenance")
