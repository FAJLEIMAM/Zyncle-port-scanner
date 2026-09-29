"""add matcher name to findings

Revision ID: f334b826f122
Revises: 2b9f22232e42
Create Date: 2026-09-30 01:33:11.499349

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "f334b826f122"
down_revision: Union[str, Sequence[str], None] = "2b9f22232e42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "findings",
        sa.Column(
            "matcher_name",
            sa.String(length=255),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("findings", "matcher_name")