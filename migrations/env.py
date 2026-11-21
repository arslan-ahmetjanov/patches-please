"""Окружение Alembic.

Строка подключения не хранится в alembic.ini: её отдаёт `app.db.database_url()`,
поэтому контейнеры и миграции с хоста используют один и тот же DATABASE_URL.
Метаданные берутся из моделей, чтобы автогенерация видела все таблицы.
"""

import logging
from typing import Any, TextIO

from alembic import context
from sqlalchemy import Connection

from app import db
from app.auth import models  # noqa: F401 — регистрирует таблицы в Base.metadata
from app.projects import models as project_models  # noqa: F401 — то же для projects
from app.tokens import models as token_models  # noqa: F401 — то же для project_tokens

config = context.config
target_metadata = db.Base.metadata


def _configure(
    connection: Connection | None, url: str | None, output_buffer: TextIO | None
) -> None:
    """Общие настройки Alembic для онлайн- и офлайн-режима."""
    context.configure(
        connection=connection,
        url=url,
        target_metadata=target_metadata,
        compare_type=True,
        literal_binds=connection is None,
        dialect_opts={"paramstyle": "named"},
        output_buffer=output_buffer,
    )


def run_migrations_offline() -> None:
    """Генерирует SQL без подключения к БД: `alembic upgrade head --sql`."""
    output_buffer: Any = config.attributes.get("output_buffer")
    _configure(None, db.database_url(), output_buffer)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Применяет миграции к живой базе."""
    engine = db.build_engine()
    with engine.connect() as connection:
        _configure(connection, None, None)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    run_migrations_online()
