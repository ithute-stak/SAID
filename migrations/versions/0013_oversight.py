"""Phase 17 central supervisory checkpoints and retention legal holds."""
from alembic import op
import sqlalchemy as sa

revision = "0013_oversight"
down_revision = "0012_appeals"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("ceir_mock_checkpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_investigations.id"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("head_digest", sa.String(64), nullable=False),
        sa.Column("reason_reference", sa.String(120), nullable=False),
        sa.Column("checkpoint_digest", sa.String(64), nullable=False),
        sa.Column("recorded_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("investigation_id", "sequence",
                            name="uq_ceir_checkpoint_case_sequence"))
    op.create_index("ix_ceir_mock_checkpoints_investigation_id",
                    "ceir_mock_checkpoints", ["investigation_id"])
    op.create_table("ceir_mock_legal_holds",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_investigations.id"), nullable=False),
        sa.Column("reason_reference", sa.String(120), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("investigation_id", name="uq_ceir_legal_hold_case"))
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_checkpoints", "ceir_mock_legal_holds"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"""CREATE POLICY {table}_central_only ON {table}
                FOR ALL USING (current_setting('said.central', true) = 'true')
                WITH CHECK (current_setting('said.central', true) = 'true')""")
        for table in ("ceir_mock_checkpoints", "ceir_mock_legal_holds"):
            op.execute(f"""CREATE TRIGGER {table}_no_update_delete
                BEFORE UPDATE OR DELETE ON {table}
                FOR EACH ROW EXECUTE FUNCTION said_reject_review_ledger_mutation()""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_checkpoints", "ceir_mock_legal_holds"):
            op.execute(f"DROP TRIGGER IF EXISTS {table}_no_update_delete ON {table}")
            op.execute(f"DROP POLICY IF EXISTS {table}_central_only ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_table("ceir_mock_legal_holds")
    op.drop_index("ix_ceir_mock_checkpoints_investigation_id",
                  table_name="ceir_mock_checkpoints")
    op.drop_table("ceir_mock_checkpoints")
