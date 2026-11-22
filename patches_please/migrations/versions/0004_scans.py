"""scans: история прогонов проверок (T-008, FR-001, FR-007).

Схема повторяет таблицу `scans` из раздела «Данные и контракты» плана:
UUID первичный ключ, внешний ключ на проект с каскадом, коммит, ref, провайдер,
статус, вердикт, jsonb-тайминги и причина ошибки. `started_at` и `finished_at`
допускают NULL: прогон создаётся в очереди, а работу начинает воркер.
Индекс `(project_id, started_at DESC)` — из плана: история проекта читается
свежими сверху. Миграция обратима: downgrade удаляет индекс и таблицу.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=False),
        sa.Column("ref", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'queued'"),
            nullable=False,
        ),
        sa.Column("verdict", sa.String(length=10), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("timings", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_scans_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        comment="История прогонов проверок",
    )
    op.create_index(
        "ix_scans_project_id_started_at",
        "scans",
        ["project_id", sa.text("started_at DESC")],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_scans_project_id_started_at", table_name="scans")
    op.drop_table("scans")
