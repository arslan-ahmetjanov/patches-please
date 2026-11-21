"""Схема в PostgreSQL: таблицы миграции, сохранность строк и откат тестовой сессии.

Интеграционные тесты работают с отдельной базой `security_gate_test`: фикстуры
создают её, применяют миграции и откатывают изменения после каждого теста.
Нужен запущенный стек (`docker compose up -d`): `uv run pytest -m integration`.
"""

import uuid

import pytest
from sqlalchemy import Engine, create_engine, delete, inspect, select
from sqlalchemy.orm import Session, sessionmaker

from app.auth.models import User

pytestmark = pytest.mark.integration


def test_t_002_schema_has_users_and_sessions(db_engine: Engine) -> None:
    """Миграция создаёт обе таблицы из плана."""
    tables = set(inspect(db_engine).get_table_names())

    assert {"users", "sessions"} <= tables


def test_nfr_005_user_survives_engine_reconnect(db_engine: Engine) -> None:
    """Строка из users видна из нового подключения к той же базе (данные в volume)."""
    email = f"t-002-{uuid.uuid4().hex}@example.com"
    writer = create_engine(db_engine.url)
    reader = create_engine(db_engine.url)
    try:
        with sessionmaker(bind=writer)() as session:
            session.add(User(email=email, password_hash="не-настоящий-хеш"))
            session.commit()

        with sessionmaker(bind=reader)() as session:
            stored = session.scalar(select(User).where(User.email == email))
            assert stored is not None
            assert stored.role == "user", "server_default роли должен применяться в БД"
            assert stored.created_at is not None
    finally:
        writer.dispose()
        reader.dispose()
        with sessionmaker(bind=db_engine)() as session:
            session.execute(delete(User).where(User.email == email))
            session.commit()


def test_t_003_db_session_rolls_back_changes(db_engine: Engine, db_session: Session) -> None:
    """Запись из db_session не видна другим подключениям и откатывается после теста."""
    email = f"t-003-{uuid.uuid4().hex}@example.com"
    db_session.add(User(email=email, password_hash="не-настоящий-хеш"))
    db_session.commit()

    with sessionmaker(bind=db_engine)() as other:
        assert other.scalar(select(User).where(User.email == email)) is None
