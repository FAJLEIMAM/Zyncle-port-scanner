"""add scan profile

Revision ID: 4f60f45cfecf
Revises: f334b826f122
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4f60f45cfecf"
down_revision: Union[str, Sequence[str], None] = "f334b826f122"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add scan profile to existing scans."""

    # Add nullable first so existing rows remain valid.
    op.add_column(
        "scans",
        sa.Column(
            "profile",
            sa.String(length=20),
            nullable=True,
        ),
    )

    # Existing scans use the default/common discovery profile.
    op.execute(
        "UPDATE scans SET profile = 'common' WHERE profile IS NULL"
    )

    # New database rows also get common unless explicitly set.
    op.alter_column(
        "scans",
        "profile",
        existing_type=sa.String(length=20),
        nullable=False,
        server_default="common",
    )


def downgrade() -> None:
    """Remove scan profile."""

    op.drop_column("scans", "profile")