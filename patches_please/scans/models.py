"""Прогоны проверок: приём, статус и вердикт (T-008, FR-001, FR-007).

Строка создаётся в момент приёма запроса от CI со статусом `queued`: время
создания — это время приёма. `started_at` заполняет воркер, когда берёт задачу
(`queued → running`), `finished_at` — завершение прогона (`done`/`error`);
переходы проверяет `patches_please/scans/service.py` (T-009, FR-026). Провайдер хранится
как есть и на проверку не влияет: FR-019 требует одного поведения в GitHub
Actions и GitLab CI.

`timings` — jsonb под метрики прогона (T-016), `error` — причина статуса `error`
(T-009). Число находок по severity считается из `findings` (T-012), отдельной
колонки под него нет.

`FindingRecord` — сохранённая находка прогона (T-014): пара `(scan_id, fingerprint)`
уникальна, потому что дубли внутри прогона схлопнуты (FR-029), а `state` хранит
метку классификации `new`/`existing` (FR-016). Исправленные находки в таблицу не
попадают: их в текущем прогоне нет (delta-009).
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    desc,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from patches_please.db import Base


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
    # Время приёма запроса; начало и завершение ставит обработка прогона.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingRecord(Base):
    """Находка прогона: нормализованные поля FR-003 и метка классификации (FR-016)."""

    __tablename__ = "findings"
    # Ограничения и индексы повторяют миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_id_fingerprint"),
        Index("ix_findings_scan_id_severity", "scan_id", "severity"),
        Index("ix_findings_fingerprint", "fingerprint"),
        {"comment": "Находки прогонов"},
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    # SHA-256 в hex: 64 символа. Вместе с прогоном даёт уникальность находки.
    fingerprint: Mapped[str] = mapped_column(String(64))
    scanner: Mapped[str] = mapped_column(String(50))
    rule_id: Mapped[str] = mapped_column(String(255))
    finding_type: Mapped[str] = mapped_column(String(20))
    severity: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    # Только `new` и `existing`: `fixed` в текущем прогоне нет (delta-009).
    state: Mapped[str] = mapped_column(String(10))
    # Заполняет T-015: исключённая находка остаётся в отчёте, но не в вердикте.
    excluded: Mapped[bool] = mapped_column(Boolean, server_default=text("false"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
