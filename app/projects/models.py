"""Проекты и членство пользователей в них (T-005, FR-017).

Изоляция данных держится на `project_members`: строка членства — единственное
основание видеть проект. Создатель проекта получает роль `owner`, остальные
участники — `member`; на это решение будет опираться проверка прав T-025.

Обе связи членства удаляются каскадом: проект нельзя оставить без участников,
а удаление учётной записи не должно блокироваться её членством.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

# Роль создателя проекта: полные права в проекте.
OWNER_ROLE = "owner"
# Роль приглашённого участника: видит данные проекта, но управление — у владельца.
MEMBER_ROLE = "member"


class Project(Base):
    """Проект — объект проверки: репозиторий и ветка по умолчанию."""

    __tablename__ = "projects"
    # Комментарий повторяет миграцию: иначе `alembic check` видит расхождение.
    __table_args__ = {"comment": "Проекты, подключённые к проверке"}

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    name: Mapped[str] = mapped_column(String(200))
    # Slug виден в адресах страниц, поэтому уникален и состоит из безопасных символов.
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    # Адрес репозитория необязателен: проект можно завести до подключения CI.
    repo_url: Mapped[str | None] = mapped_column(Text)
    default_branch: Mapped[str] = mapped_column(String(255), server_default=text("'main'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ProjectMember(Base):
    """Членство пользователя в проекте: правая граница изоляции данных."""

    __tablename__ = "project_members"
    __table_args__ = {"comment": "Членство пользователей в проектах"}

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # Индекс по user_id: основной запрос — «проекты, где я участник».
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(32), server_default=text("'member'"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
