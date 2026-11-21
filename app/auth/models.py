"""Модели учётных записей и сессий браузера (T-002, NFR-005).

Схема соответствует разделу «Данные и контракты» плана: `users` и `sessions`
с UUID-ключами. Пароли и токены хранятся только в виде хешей.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    """Учётная запись для входа в интерфейс Security Gate."""

    __tablename__ = "users"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Учётные записи для входа в интерфейс"}

    # Идентификатор генерирует PostgreSQL: строку можно вставить и обычным SQL.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    email: Mapped[str] = mapped_column(String(320), unique=True)
    # Хеш пароля, сам пароль не хранится.
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), server_default=text("'user'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class UserSession(Base):
    """Сессия браузера: ключ — хеш cookie-токена, срок жизни ограничен."""

    __tablename__ = "sessions"

    # SHA-256 в hex занимает 64 символа; открытый токен в БД не попадает.
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
