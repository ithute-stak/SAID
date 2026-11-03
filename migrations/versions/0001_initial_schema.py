"""Initial SAID Phase 1 and 2 tables.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("imei", sa.String(15), nullable=False),
        sa.Column("owner_reference", sa.String(120), nullable=False),
        sa.Column("make", sa.String(80), nullable=False),
        sa.Column("model", sa.String(80), nullable=False),
        sa.Column("verification_status", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_devices_imei", "devices", ["imei"], unique=True)
    op.create_table(
        "theft_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("incident_reference", sa.String(120), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_id", sa.String(36), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "ownership_claims",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("device_id", sa.String(36), sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("applicant_reference", sa.String(120), nullable=False),
        sa.Column("evidence_reference", sa.String(120), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("device_id", name="uq_one_ownership_claim_per_device_phase2"),
    )
    op.create_index("ix_ownership_claims_device_id", "ownership_claims", ["device_id"], unique=False)

def downgrade():
    # Development-only rollback; DO NOT run on any DB containing real records.
    op.drop_index("ix_ownership_claims_device_id", table_name="ownership_claims")
    op.drop_table("ownership_claims")
    op.drop_table("audit_events")
    op.drop_table("theft_reports")
    op.drop_index("ix_devices_imei", table_name="devices")
    op.drop_table("devices")
