"""CEIR mock EIR outbox/event ledger. No external connectivity.

Revision ID: 0008_mock_exchange
Revises: 0007_ceir_sandbox
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_mock_exchange"
down_revision = "0007_ceir_sandbox"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ceir_mock_exchanges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("operator_code", sa.String(40), nullable=False),
        sa.Column("simulation_id", sa.String(36), sa.ForeignKey("ceir_simulations.id"), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False),
        sa.Column("proposed_status", sa.String(30), nullable=False),
        sa.Column("state", sa.String(35), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("operator_code", "simulation_id", "revision", "mode",
                            name="uq_mock_exchange_delivery"),
    )
    op.create_index("ix_ceir_mock_exchanges_simulation_id", "ceir_mock_exchanges",
                    ["simulation_id"])
    op.create_table(
        "ceir_mock_exchange_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("exchange_id", sa.String(36), sa.ForeignKey("ceir_mock_exchanges.id"), nullable=False),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("actor_reference", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ceir_mock_exchange_events_exchange_id",
                    "ceir_mock_exchange_events", ["exchange_id"])
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_exchanges", "ceir_mock_exchange_events"):
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            op.execute(f"""CREATE POLICY {table}_central_only ON {table}
                FOR ALL USING (current_setting('said.central', true) = 'true')
                WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in ("ceir_mock_exchange_events", "ceir_mock_exchanges"):
            op.execute(f"DROP POLICY IF EXISTS {table}_central_only ON {table}")
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ceir_mock_exchange_events_exchange_id", table_name="ceir_mock_exchange_events")
    op.drop_table("ceir_mock_exchange_events")
    op.drop_index("ix_ceir_mock_exchanges_simulation_id", table_name="ceir_mock_exchanges")
    op.drop_table("ceir_mock_exchanges")
