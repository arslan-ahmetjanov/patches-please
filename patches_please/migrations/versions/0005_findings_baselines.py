"""findings, baselines, baseline_items: находки и база сравнения (T-014, FR-006, FR-016).

Схема повторяет раздел «Данные и контракты» плана. `findings` хранит нормализованные
находки прогона: пару `(scan_id, fingerprint)` делает уникальной дедупликация внутри
прогона (FR-029), а `state` — метку `new`/`existing` из классификации (FR-016).
`fixed` в колонку не попадает: исправленной находки в текущем прогоне нет, поэтому
она отдаётся отдельным списком fingerprints (delta-009).

`baselines` — один снимок на проект: `project_id` уникален, повторная установка
заменяет элементы, а не создаёт вторую строку. `baseline_items` хранит только
fingerprints: подробности читаются из прогона, с которого снят baseline, поэтому
`scan_id` при удалении прогона обнуляется (`SET NULL`), а набор остаётся.
Миграция обратима: downgrade удаляет индексы и таблицы, не затрагивая
`scans` и `projects`.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("scanner", sa.String(length=50), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("finding_type", sa.String(length=20), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        # Только `new` и `existing`: значения проверяет классификация (FR-016),
        # в базе ограничение не ставится — набор меток может вырасти.
        sa.Column("state", sa.String(length=10), nullable=False),
        sa.Column("excluded", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_findings_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint("scan_id", "fingerprint", name=op.f("uq_findings_scan_id_fingerprint")),
        comment="Находки прогонов",
    )
    op.create_index(
        "ix_findings_scan_id_severity",
        "findings",
        ["scan_id", "severity"],
        unique=False,
    )
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"], unique=False)

    op.create_table(
        "baselines",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        # Прогон-источник может быть удалён: fingerprints остаются, ссылка пустеет.
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name=op.f("fk_baselines_project_id_projects"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_baselines_scan_id_scans"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_baselines")),
        sa.UniqueConstraint("project_id", name=op.f("uq_baselines_project_id")),
        comment="Зафиксированные baseline проектов",
    )

    op.create_table(
        "baseline_items",
        sa.Column("baseline_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["baseline_id"],
            ["baselines.id"],
            name=op.f("fk_baseline_items_baseline_id_baselines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("baseline_id", "fingerprint", name=op.f("pk_baseline_items")),
        comment="Fingerprints baseline",
    )


def downgrade() -> None:
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_index("ix_findings_scan_id_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_table("baseline_items")
    op.drop_table("baselines")
