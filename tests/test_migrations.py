"""Миграции Alembic: один head, таблицы схемы, обратимость (T-002, T-006, NFR-005).

Тест работает без базы: Alembic в офлайн-режиме генерирует SQL, который он применил
бы к PostgreSQL. Это проверяет и upgrade, и downgrade на каждой машине и в CI.
"""

import io
from pathlib import Path
from typing import Literal

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = ROOT / "alembic.ini"


def _config() -> Config:
    return Config(str(ALEMBIC_INI))


def _offline_sql(direction: Literal["upgrade", "downgrade"], revision: str) -> str:
    """SQL миграции без подключения к базе, через буфер конфигурации Alembic."""
    buffer = io.StringIO()
    config = _config()
    config.attributes["output_buffer"] = buffer
    if direction == "upgrade":
        command.upgrade(config, revision, sql=True)
    else:
        command.downgrade(config, revision, sql=True)
    return buffer.getvalue()


def test_t_002_single_head() -> None:
    """В репозитории ровно одна голова: миграции линейны и применяются по порядку."""
    heads = ScriptDirectory.from_config(_config()).get_heads()

    assert heads == ["0003"]


def test_t_002_upgrade_creates_users_and_sessions() -> None:
    """Upgrade создаёт обе таблицы с полями из плана."""
    sql = _offline_sql("upgrade", "head")

    assert "CREATE TABLE users" in sql
    assert "CREATE TABLE sessions" in sql
    for column in ("email", "password_hash", "role", "created_at"):
        assert column in sql
    for column in ("token_hash", "user_id", "expires_at"):
        assert column in sql
    assert "gen_random_uuid()" in sql
    assert "FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE" in sql


def test_t_002_downgrade_drops_tables_in_reverse_order() -> None:
    """Downgrade удаляет sessions раньше users: внешний ключ не блокирует откат."""
    sql = _offline_sql("downgrade", "head:base")

    assert "DROP TABLE sessions" in sql
    assert "DROP TABLE users" in sql
    assert sql.index("DROP TABLE sessions") < sql.index("DROP TABLE users")


def test_t_006_upgrade_creates_project_tokens() -> None:
    """Третья миграция добавляет токены проекта: хеш уникален, проект — по каскаду."""
    sql = _offline_sql("upgrade", "head")

    assert "CREATE TABLE project_tokens" in sql
    for column in ("project_id", "name", "token_hash", "created_at", "last_used_at", "revoked_at"):
        assert column in sql
    assert "UNIQUE (token_hash)" in sql
    assert "ON DELETE CASCADE" in sql
    assert "CREATE INDEX ix_project_tokens_project_id ON project_tokens (project_id)" in sql


def test_t_006_downgrade_drops_project_tokens_after_index() -> None:
    """Downgrade удаляет индекс раньше таблицы и не задевает projects."""
    sql = _offline_sql("downgrade", "head:base")

    index_drop = sql.index("DROP INDEX ix_project_tokens_project_id")
    table_drop = sql.index("DROP TABLE project_tokens")
    projects_drop = sql.index("DROP TABLE projects")
    assert index_drop < table_drop < projects_drop
