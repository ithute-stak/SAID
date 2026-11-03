"""Scope device records to authenticated institutions.

Revision ID: 0003_institution
Revises: 0002_access_audit
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_institution"
down_revision = "0002_access_audit"
branch_labels = None
depends_on = None

def upgrade():
    # Existing rows cannot be silently attributed to an institution.
    # NULL is deliberately restricted to central administrators.
    op.add_column("devices", sa.Column("institution_id", sa.String(120), nullable=True))
    op.create_index("ix_devices_institution_id", "devices", ["institution_id"], unique=False)

def downgrade():
    # Destructive operation: never perform on a populated production database.
    op.drop_index("ix_devices_institution_id", table_name="devices")
    op.drop_column("devices", "institution_id")
