"""policies: пороги вердикта проекта (T-017, FR-004, FR-014).

Схема повторяет строку `policies` из раздела «Данные и контракты» плана:
пороги по severity, режим fail-open/fail-closed и общий таймаут сканеров.
Политика одна на проект, поэтому первичный ключ — `project_id`: отдельный
идентификатор не нужен, а каскад удаляет политику вместе с проектом.

`block_severities` — массив уровней шкалы FR-014; умолчание `{critical,high}`
совпадает с предусловием S-002 и с политикой по умолчанию в коде, пока строки
нет. `fail_mode` и `scanner_timeout_sec` объявлены сразу, чтобы не делать вторую
миграцию: режим деградации использует T-019, таймаут — T-011. В T-017 на вердикт
влияет только `block_severities`.

Миграция обратима: downgrade удаляет таблицу, не затрагивая `projects`.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Уровни шкалы FR-014; умолчание совпадает с политикой по умолчанию в коде (S-002).
        sa.Column(
            "block_severities",
            postgresql.ARRAY(sa.String(length=10)),
            server_default=sa.text("'{critical,high}'::varchar[]"),
            nullable=False,
        ),
        # Режим деградации сканера: `open` или `closed`, использует T-019.
        sa.Column(
            "fail_mode",
            sa.String(length=20),
            server_default=sa.text("'open'"),
            nullable=False,
        ),
        # Общий таймаут сканеров прогона в секундах, использует T-011/T-019.
        sa.Column(
            "scanner_timeout_sec",
            sa.Integer(),
            server_default=sa.text("300"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_policies_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("project_id", name=op.f("pk_policies")),
        comment="Политики вердикта проектов",
    )


def downgrade() -> None:
    op.drop_table("policies")
