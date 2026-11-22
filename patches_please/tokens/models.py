"""Токены проектов: доступ CI к API (T-006, FR-024, FR-025).

Токен — единственный ключ, которым CI подтверждает право на проект, поэтому
в базе лежит только его SHA-256: открытое значение существует в ответе на
создание и в памяти вызывающего кода. Отзыв мягкий — строка остаётся, чтобы
история токенов и будущий аудит (T-015) не терялись.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from patches_please.db import Base


class ProjectToken(Base):
    """Токен доступа к проекту. Открытого значения в строке нет — только хеш."""

    __tablename__ = "project_tokens"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Токены проектов для доступа из CI"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    # Индекс по project_id: основной запрос — «токены этого проекта».
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100))
    # SHA-256 в hex: 64 символа. Уникален, потому что по нему идёт поиск токена.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Заполняется при успешной проверке токена (T-008).
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Заполняется при отзыве; NULL — токен действует.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
