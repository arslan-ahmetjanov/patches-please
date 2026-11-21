"""Общие фикстуры pytest: HTTP-клиент приложения и тестовая база (T-003, NFR-001).

HTTP-тесты идут в приложение через ASGI-транспорт httpx: без сетевого порта
и без TestClient, который устарел в starlette. Обвязка собрана в `AppClient`,
чтобы тесты не дублировали `asyncio.run` и настройку транспорта.

Интеграционным тестам нужна отдельная база `security_gate_test`. Фикстуры
создают её при первом обращении, применяют миграции Alembic и откатывают
изменения после каждого теста. Из `DATABASE_URL` берутся только сервер и
учётные данные, имя базы подменяется на тестовое — база стенда не затрагивается.
Полный URL тестовой базы можно задать переменной `TEST_DATABASE_URL`.
"""

import asyncio
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.engine import URL
from sqlalchemy.orm import Session
from starlette.types import ASGIApp

from app.db import database_url
from app.main import app

ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = ROOT / "alembic.ini"
TEST_DATABASE_NAME = "security_gate_test"


class AppClient:
    """Синхронный клиент приложения поверх httpx.ASGITransport."""

    def __init__(self, asgi_app: ASGIApp, base_url: str = "http://security-gate") -> None:
        self._app = asgi_app
        self._base_url = base_url

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(transport=transport, base_url=self._base_url) as client:
            return await client.request(method, url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Выполняет запрос в отдельном цикле событий: тесты остаются синхронными."""
        return asyncio.run(self._send(method, url, **kwargs))

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)


@pytest.fixture
def client() -> AppClient:
    """Клиент приложения: запрос идёт в ASGI-приложение, сеть не нужна."""
    return AppClient(app)


@contextmanager
def _environment_database_url(url: URL) -> Iterator[None]:
    """Подставляет URL базы в окружение на время миграций и восстанавливает прежнее значение.

    Alembic читает строку подключения из `app.db.database_url()`, поэтому иначе
    `command.upgrade` применил бы миграции к базе стенда.
    """
    previous = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url.render_as_string(hide_password=False)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous


def _create_database(url: URL) -> None:
    """Создаёт пустую тестовую базу, если её ещё нет."""
    name = url.database
    if name is None or not name.isidentifier():
        raise RuntimeError("Имя тестовой базы должно быть допустимым идентификатором")

    admin_engine = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as connection:
            exists = connection.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": name}
            )
            if exists is None:
                connection.execute(text(f'CREATE DATABASE "{name}"'))
    finally:
        admin_engine.dispose()


@pytest.fixture(scope="session")
def test_db_url() -> URL:
    """URL тестовой базы: сервер из `DATABASE_URL`, база — `security_gate_test`."""
    override = os.environ.get("TEST_DATABASE_URL")
    if override:
        return make_url(override)
    return make_url(database_url()).set(database=TEST_DATABASE_NAME)


@pytest.fixture(scope="session")
def migrated_test_database(test_db_url: URL) -> URL:
    """Готовит тестовую базу один раз за прогон: создание и миграции до head."""
    _create_database(test_db_url)
    config = Config(str(ALEMBIC_INI))
    with _environment_database_url(test_db_url):
        command.upgrade(config, "head")
    return test_db_url


@pytest.fixture
def db_engine(migrated_test_database: URL) -> Iterator[Engine]:
    """Движок тестовой базы; соединение открывается лениво, при первом запросе."""
    engine = create_engine(migrated_test_database)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(db_engine: Engine) -> Iterator[Session]:
    """Сессия в транзакции, которая откатывается после теста: мусор не остаётся."""
    connection = db_engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
