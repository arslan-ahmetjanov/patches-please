"""Baseline проекта: снимок fingerprints выбранного прогона (T-014, FR-006).

Baseline у проекта один: `project_id` уникален, повторная установка заменяет
элементы. Хранятся только fingerprints — подробности находки читаются из
прогона-источника, а `scan_id` при его удалении обнуляется (`SET NULL`), набор
элементов при этом остаётся (delta-009).

Связей `relationship` нет намеренно: элементы baseline заменяются явно в
`patches_please/policy/baseline.py`, и ленивая загрузка коллекции тут не нужна.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from patches_please.db import Base


class Baseline(Base):
    """Зафиксированный набор fingerprints проекта: один снимок на проект."""

    __tablename__ = "baselines"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Зафиксированные baseline проектов"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    # Один baseline на проект: повторная установка переиспользует строку.
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        unique=True,
    )
    # Прогон, с которого снят снимок; после его удаления ссылка пустеет.
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class BaselineItem(Base):
    """Fingerprint находки, зафиксированной в baseline."""

    __tablename__ = "baseline_items"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Fingerprints baseline"}

    baseline_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("baselines.id", ondelete="CASCADE"),
        primary_key=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
