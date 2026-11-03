"""Record authenticated reviewer identifiers on claims and audit events.

Revision ID: 0002_access_audit
Revises: 0001_initial
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_access_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("ownership_claims", sa.Column("reviewed_by", sa.String(200), nullable=True))
    op.add_column("audit_events", sa.Column("actor_reference", sa.String(200), nullable=True))

def downgrade():
    # Destructive loss of audit attribution: development only.
    op.drop_column("audit_events", "actor_reference")
    op.drop_column("ownership_claims", "reviewed_by")
