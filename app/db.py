"""Подключение к PostgreSQL: движок SQLAlchemy, фабрика сессий, база моделей.

Строка подключения берётся из переменной окружения `DATABASE_URL`. Контейнеры
`api` и `worker` получают значение из `docker-compose.yml` (хост `postgres`),
а миграции с хоста запускаются без переменной и используют значение по умолчанию
на `localhost`. Так конфиг не дублируется: имя переменной одно.
"""

import os
from collections.abc import Iterator
from typing import Final

from sqlalchemy import Engine, MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DEFAULT_DATABASE_URL: Final = (
    "postgresql+psycopg://security_gate:security_gate_local@localhost:5432/security_gate"
)

# Имена ограничений задаются явно: безымянные объекты неудобно удалять в downgrade,
# а Alembic с автогенерацией сравнивает их по именам.
NAMING_CONVENTION: Final = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def database_url() -> str:
    """Строка подключения из окружения или локальное значение по умолчанию."""
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


class Base(DeclarativeBase):
    """Общая база декларативных моделей; её `metadata` читает Alembic."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


def build_engine(url: str | None = None) -> Engine:
    """Создаёт движок SQLAlchemy. Соединение открывается лениво, при первом запросе."""
    return create_engine(url or database_url(), pool_pre_ping=True)


engine = build_engine()

# expire_on_commit=False: объекты остаются читаемыми после коммита, а не превращаются
# в «просроченные» и не требуют лишнего запроса ради того же значения.
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """Зависимость FastAPI: сессия БД на время запроса, закрывается после ответа.

    Роутеры получают её через `Depends(get_db)`; тесты подменяют её на сессию
    в откатываемой транзакции, поэтому `app.dependency_overrides` работает.
    """
    with SessionLocal() as session:
        yield session
