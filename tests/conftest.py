"""Общие фикстуры pytest: HTTP-клиент приложения и тестовая база (T-003, NFR-001).

HTTP-тесты идут в приложение через ASGI-транспорт httpx: без сетевого порта
и без TestClient, который устарел в starlette. Обвязка собрана в `AppClient`,
чтобы тесты не дублировали `asyncio.run` и настройку транспорта.

`AppClient` помнит cookie между запросами (T-004, FR-022, FR-023), поэтому цепочка
«вход → сессия → выход» проверяется тем же клиентом. Фикстура `db_client`
подменяет зависимость `get_db` на тестовую сессию, а `client` остаётся без базы:
healthcheck и валидация входных данных работают и без неё.

Интеграционным тестам нужна отдельная база `patches_please_test`. Фикстуры
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

from patches_please.db import database_url, get_db
from patches_please.main import app

ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = ROOT / "alembic.ini"
TEST_DATABASE_NAME = "patches_please_test"


class AppClient:
    """Синхронный клиент приложения поверх httpx.ASGITransport.

    Клиент помнит cookie между запросами: иначе не проверить цепочку
    «вход → сессия в cookie → выход». Наружу он отдаёт `cookies`, а `clear_cookies`
    забывает их, когда нужен анонимный запрос.
    """

    def __init__(self, asgi_app: ASGIApp, base_url: str = "http://patches-please") -> None:
        self._app = asgi_app
        self._base_url = base_url
        self.cookies = httpx.Cookies()

    async def _send(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=self._base_url,
            cookies=self.cookies,
        ) as client:
            response = await client.request(method, url, **kwargs)
            # Клиент живёт один запрос, поэтому jar переносим в атрибут AppClient.
            self.cookies = client.cookies
            return response

    def clear_cookies(self) -> None:
        """Забывает сохранённые cookie: следующий запрос уходит без сессии."""
        self.cookies = httpx.Cookies()

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
    """Клиент приложения: запрос идёт в ASGI-приложение, сеть не нужна.

    База не подключается: healthcheck и валидация входных данных работают без неё.
    Тестам, которым нужна БД, — фикстура `db_client`.
    """
    return AppClient(app)


@pytest.fixture
def db_client(db_session: Session) -> Iterator[AppClient]:
    """Клиент приложения с базой: `get_db` подменён на сессию из `db_session`.

    Так приложение в тестах не берёт engine из `DATABASE_URL` (это была бы база
    стенда), а все записи откатываются вместе с транзакцией фикстуры.
    """

    def _get_db() -> Session:
        return db_session

    app.dependency_overrides[get_db] = _get_db
    try:
        yield AppClient(app)
    finally:
        app.dependency_overrides.pop(get_db, None)


@contextmanager
def _environment_database_url(url: URL) -> Iterator[None]:
    """Подставляет URL базы в окружение на время миграций и восстанавливает прежнее значение.

    Alembic читает строку подключения из `patches_please.db.database_url()`, поэтому иначе
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
    """URL тестовой базы: сервер из `DATABASE_URL`, база — `patches_please_test`."""
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
