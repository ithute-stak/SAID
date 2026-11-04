"""Phase 15 separate-review and integrity ledger, revision 0011_governance."""
from alembic import op
import sqlalchemy as sa

revision = "0011_governance"
down_revision = "0010_intelligence"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("ceir_mock_investigations",
                  sa.Column("opened_by", sa.String(200), nullable=True))
    op.create_table(
        "ceir_mock_review_ledger",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(36),
                  sa.ForeignKey("ceir_mock_investigations.id"), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("actor_reference", sa.String(200), nullable=False),
        sa.Column("decision_reference", sa.String(120), nullable=False),
        sa.Column("previous_digest", sa.String(64), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("investigation_id", "sequence",
                            name="uq_ceir_review_ledger_sequence"),
    )
    op.create_index("ix_ceir_mock_review_ledger_investigation_id",
                    "ceir_mock_review_ledger", ["investigation_id"])
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE ceir_mock_review_ledger ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_review_ledger FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY ceir_mock_review_ledger_central_only ON ceir_mock_review_ledger
            FOR ALL USING (current_setting('said.central', true) = 'true')
            WITH CHECK (current_setting('said.central', true) = 'true')""")
        # Even a compromised DML-only runtime cannot rewrite or erase ledger history.
        op.execute("""CREATE FUNCTION said_reject_review_ledger_mutation()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'SAID review ledger is append-only';
            END; $$""")
        op.execute("""CREATE TRIGGER ceir_review_ledger_no_update_delete
            BEFORE UPDATE OR DELETE ON ceir_mock_review_ledger
            FOR EACH ROW EXECUTE FUNCTION said_reject_review_ledger_mutation()""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS ceir_review_ledger_no_update_delete ON ceir_mock_review_ledger")
        op.execute("DROP FUNCTION IF EXISTS said_reject_review_ledger_mutation()")
        op.execute("DROP POLICY IF EXISTS ceir_mock_review_ledger_central_only ON ceir_mock_review_ledger")
        op.execute("ALTER TABLE ceir_mock_review_ledger NO FORCE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE ceir_mock_review_ledger DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ceir_mock_review_ledger_investigation_id",
                  table_name="ceir_mock_review_ledger")
    op.drop_table("ceir_mock_review_ledger")
    op.drop_column("ceir_mock_investigations", "opened_by")
