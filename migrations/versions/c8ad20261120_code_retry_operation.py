"""Track activation vs renewal for account-scoped idempotent code retries.

Revision ID: c8ad20261120
Revises: b85625159f44
"""
from alembic import op
import sqlalchemy as sa

revision = "c8ad20261120"
down_revision = "b85625159f44"
branch_labels = None
depends_on = None


def upgrade():
    # Old redeemed rows have NULL operation and intentionally cannot be replayed
    # as idempotent retries; their original intent cannot be reconstructed safely.
    op.add_column("activation_codes", sa.Column("redemption_operation", sa.String(length=20), nullable=True))


def downgrade():
    op.drop_column("activation_codes", "redemption_operation")
