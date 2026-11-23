"""Baseline проекта и исключения находок (T-014, T-015).

Baseline у проекта один: `project_id` уникален, повторная установка заменяет
элементы. Хранятся только fingerprints — подробности находки читаются из
прогона-источника, а `scan_id` при его удалении обнуляется (`SET NULL`), набор
элементов при этом остаётся (delta-009).

Исключение (`exceptions`) привязано к проекту и правилу, ограничено `path_glob`
и действует до `expires_at`, пока не отозвано (`revoked_at`). Пока исключение
активно, находка не влияет на вердикт; после истечения срока или отзыва она
снова учитывается (FR-011, FR-012). Логика — в
`patches_please/policy/exceptions.py`.

Связей `relationship` нет намеренно: элементы baseline заменяются явно в
`patches_please/policy/baseline.py`, а исключения читаются запросом по проекту,
и ленивая загрузка коллекций тут не нужна.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, text
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


class ExceptionRecord(Base):
    """Исключение находки: правило, путь, причина, автор и срок (FR-011, FR-012).

    Отзыв мягкий: строка остаётся, `revoked_at` только закрывает действие.
    Автор не обнуляется при удалении учётной записи: без автора исключение
    перестало бы отвечать FR-011, поэтому внешний ключ не даёт удалить
    пользователя, пока на него ссылаются исключения.
    """

    __tablename__ = "exceptions"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Исключения находок"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Правило, к которому относится исключение; совпадение точное.
    rule_id: Mapped[str] = mapped_column(String(255))
    # Шаблон пути находки; сопоставление — `fnmatch.fnmatchcase` (FR-011).
    path_glob: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    author_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Срок действия: после него находка снова учитывается (FR-012).
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # NULL — исключение действует; время отзыва закрывает его досрочно.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
