"""Central-only CEIR sandbox. No actual EIR/network control lists.

Revision ID: 0007_ceir_sandbox
Revises: 0006_link_intents
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_ceir_sandbox"
down_revision = "0006_link_intents"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "ceir_simulations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False, unique=True),
        sa.Column("proposed_status", sa.String(30), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ceir_simulation_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("simulation_id", sa.String(36), sa.ForeignKey("ceir_simulations.id"), nullable=False),
        sa.Column("proposed_status", sa.String(30), nullable=False),
        sa.Column("reason_reference", sa.String(120), nullable=False),
        sa.Column("actor_reference", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ceir_simulation_events_simulation_id", "ceir_simulation_events", ["simulation_id"])
    if op.get_bind().dialect.name == "postgresql":
        for name in ("ceir_simulations", "ceir_simulation_events"):
            op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
        op.execute("""CREATE POLICY ceir_simulations_central ON ceir_simulations FOR ALL
            USING (current_setting('said.central', true) = 'true')
            WITH CHECK (current_setting('said.central', true) = 'true')""")
        op.execute("""CREATE POLICY ceir_simulation_events_central ON ceir_simulation_events FOR ALL
            USING (current_setting('said.central', true) = 'true')
            WITH CHECK (current_setting('said.central', true) = 'true')""")

def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for name, policy in (("ceir_simulation_events", "ceir_simulation_events_central"), ("ceir_simulations", "ceir_simulations_central")):
            op.execute(f"DROP POLICY IF EXISTS {policy} ON {name}")
            op.execute(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE {name} DISABLE ROW LEVEL SECURITY")
    op.drop_index("ix_ceir_simulation_events_simulation_id", table_name="ceir_simulation_events")
    op.drop_table("ceir_simulation_events")
    op.drop_table("ceir_simulations")
