"""project_tokens: токены проектов для доступа из CI (T-006, FR-024, FR-025).

Схема повторяет раздел «Данные и контракты» плана: UUID первичный ключ,
внешний ключ на проект с каскадом, только хеш токена. `last_used_at` и
`revoked_at` допускают NULL: токен может ни разу не использоваться и
действует, пока не отозван. Миграция обратима: downgrade удаляет индекс и
таблицу.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "project_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_project_tokens_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_project_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_project_tokens_token_hash")),
        comment="Токены проектов для доступа из CI",
    )
    op.create_index(
        op.f("ix_project_tokens_project_id"), "project_tokens", ["project_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_project_tokens_project_id"), table_name="project_tokens")
    op.drop_table("project_tokens")
