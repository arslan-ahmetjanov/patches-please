"""Событие журнала аудита (T-015, S-005).

Таблица повторяет раздел «Данные и контракты» плана: `actor`, `action`,
`entity`, `payload jsonb`, `created_at`. Событие неизменяемо — записи только
добавляются, поэтому отдельного `updated_at` нет.

`actor` — ссылка на учётную запись, но допускает NULL: действие может быть
системным (например, автоматический повтор после истечения срока), а удаление
пользователя не должно стирать историю, поэтому ключ обнуляется (`SET NULL`).
`entity` — строка вида `<тип>:<идентификатор>`: журнал общий, и тип объекта
нужен, чтобы отличать исключение от токена или политики.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from patches_please.db import Base


class AuditEvent(Base):
    """Одна запись журнала: кто, что сделал, с каким объектом и когда."""

    __tablename__ = "audit_events"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Журнал действий"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    actor: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(100))
    entity: Mapped[str] = mapped_column(String(255))
    # Только перечисленные вызывающим поля: свободный текст в журнал не попадает.
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
