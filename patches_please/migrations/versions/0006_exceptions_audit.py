"""exceptions, audit_events: исключения с сроком и журнал действий (T-015).

Схема повторяет раздел «Данные и контракты» плана. `exceptions` хранит правило,
шаблон пути, причину, автора, срок и необязательное время отзыва: отзыв мягкий,
строка остаётся ради истории (FR-011, FR-012). Автор — обязательный внешний ключ
на `users.id`: удалить учётную запись, на которую ссылается исключение, нельзя,
иначе исключение потеряло бы обязательное поле.

`audit_events` — общий журнал: актор (NULL для системных действий), действие,
объект и `payload jsonb` с явным набором полей. Журнал только дополняется,
поэтому отдельных меток изменения нет. Миграция обратима: downgrade удаляет
обе таблицы, не затрагивая `users`, `projects` и остальные данные.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "exceptions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("path_glob", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        # NULL — исключение действует; время отзыва закрывает его досрочно.
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_exceptions_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["author_id"],
            ["users.id"],
            name=op.f("fk_exceptions_author_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exceptions")),
        comment="Исключения находок",
    )

    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        # NULL — системное действие; удаление пользователя историю не стирает.
        sa.Column("actor", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("entity", sa.String(length=255), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["actor"],
            ["users.id"],
            name=op.f("fk_audit_events_actor_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        comment="Журнал действий",
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("exceptions")
