"""Прогоны проверок: приём, статус и вердикт (T-008, FR-001, FR-007).

Строка создаётся в момент приёма запроса от CI со статусом `queued`: время
создания — это время приёма, а `started_at` и `finished_at` заполняются, когда
прогон подхватит воркер (T-009). Провайдер хранится как есть и на проверку не
влияет: FR-019 требует одного поведения в GitHub Actions и GitLab CI.

`timings` — jsonb под метрики прогона (T-016), `error` — причина статуса `error`
(T-009): до этих задач оба поля остаются NULL. Число находок по severity
считается из `findings` (T-012), отдельной колонки под него нет.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, desc, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class Scan(Base):
    """Один прогон проверки: коммит, ветка, провайдер, статус и вердикт."""

    __tablename__ = "scans"
    # Индекс из плана: история проекта читается свежими сверху.
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = (
        Index("ix_scans_project_id_started_at", "project_id", desc("started_at")),
        {"comment": "История прогонов проверок"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Полный SHA-1 (40) или SHA-256 (64) в нижнем регистре: сокращения не принимаем,
    # иначе два разных коммита могли бы совпасть при дедупликации.
    commit_sha: Mapped[str] = mapped_column(String(64))
    # Git ref как его присылает CI: `main`, `refs/heads/main`, `refs/pull/1/head`.
    ref: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), server_default=text("'queued'"))
    verdict: Mapped[str | None] = mapped_column(String(10))
    error: Mapped[str | None] = mapped_column(Text)
    timings: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # Время приёма запроса; `started_at` и `finished_at` ставит воркер.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
