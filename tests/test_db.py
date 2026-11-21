"""Схема в PostgreSQL: таблицы миграции и сохранность строк между подключениями.

Требуют запущенного стека (`docker compose up -d`) и применённых миграций
(`uv run alembic upgrade head`): `uv run pytest -m integration`.
"""

import uuid

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.orm import sessionmaker

from app.auth.models import User
from app.db import build_engine

pytestmark = pytest.mark.integration


def test_t_002_schema_has_users_and_sessions() -> None:
    """Миграция создаёт обе таблицы из плана."""
    engine = build_engine()
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert {"users", "sessions"} <= tables


def test_nfr_005_user_survives_engine_reconnect() -> None:
    """Строка, записанная в users, читается из нового подключения (данные в volume)."""
    email = f"t-002-{uuid.uuid4().hex}@example.com"
    creator = build_engine()
    with sessionmaker(bind=creator)() as session:
        session.add(User(email=email, password_hash="не-настоящий-хеш"))
        session.commit()
    creator.dispose()

    reader = build_engine()
    try:
        with sessionmaker(bind=reader)() as session:
            stored = session.scalar(select(User).where(User.email == email))
            assert stored is not None
            assert stored.role == "user", "server_default роли должен применяться в БД"
            assert stored.created_at is not None
            session.delete(stored)
            session.commit()
    finally:
        reader.dispose()
