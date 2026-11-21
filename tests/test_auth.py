"""Вход и выход, хеш пароля, cookie-сессия (T-004, FR-022, FR-023).

Проверки хеширования идут без базы: они остаются в быстром job `quality`.
Тесты с БД помечены точечно `@pytest.mark.integration` и работают через `db_client`:
зависимость `get_db` подменена на сессию, которая откатывается после теста.

Маршрут `/projects` появился в T-005, но здесь проверяется только редирект после
входа, а не содержимое целевой страницы: оно — предмет `tests/test_projects.py`.
"""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import AppClient
from fastapi.exceptions import RequestValidationError
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.auth import service
from app.auth.models import User, UserSession
from app.main import app, validation_error_handler


def _create_user(session: Session, email: str, password: str) -> User:
    """Заводит учётную запись так же, как это делают тесты T-005 и T-006."""
    return service.create_user(session, email, password)


# --- Хеш пароля: быстро, без базы -------------------------------------------------


def test_fr_022_hash_password_has_scrypt_format() -> None:
    """Формат строки — `scrypt$n$r$p$соль$хеш`, параметры из задания."""
    password_hash = service.hash_password("пароль-123")

    parts = password_hash.split("$")
    assert len(parts) == 6
    assert parts[:4] == ["scrypt", "16384", "8", "1"]
    assert len(parts[4]) == 32, "соль — 16 байт в hex"
    assert len(parts[5]) == 64, "хеш — 32 байта в hex"


def test_fr_022_hash_password_uses_random_salt() -> None:
    """Два хеша одного пароля различаются: соль случайная."""
    assert service.hash_password("пароль-123") != service.hash_password("пароль-123")


def test_fr_022_verify_password_accepts_correct_password() -> None:
    password_hash = service.hash_password("пароль-123")

    assert service.verify_password("пароль-123", password_hash)


def test_fr_022_verify_password_rejects_wrong_password() -> None:
    password_hash = service.hash_password("пароль-123")

    assert not service.verify_password("пароль-124", password_hash)
    assert not service.verify_password("", password_hash)


@pytest.mark.parametrize(
    "broken_hash",
    [
        "",
        "не-хеш",
        "scrypt$16384",  # мало полей
        "scrypt$16384$8$1$00$00$лишнее",  # лишнее поле
        "bcrypt$16384$8$1$00$00",  # неизвестный алгоритм
        "scrypt$16384$8$1$zz$zz",  # соль и хеш не hex
        "scrypt$много$8$1$00$00",  # n не число
        "scrypt$0$8$1$00$00",  # n вне допустимого диапазона
        "scrypt$99999$8$1$00$00",  # n не степень двойки
        "scrypt$16384$8$1$$",  # пустые соль и хеш
        f"scrypt${2**22}$8$1$00$00",  # n выше допустимого предела
    ],
)
def test_fr_022_verify_password_rejects_broken_hash(broken_hash: str) -> None:
    """Битый или незнакомый формат — `False`, без исключения."""
    assert service.verify_password("пароль-123", broken_hash) is False


def test_fr_022_verify_password_accepts_changed_scrypt_params() -> None:
    """Параметры берутся из строки хеша: n=2**15 проходит, maxmem считается под них."""
    salt = b"0123456789abcdef"
    digest = hashlib.scrypt(
        b"parol-123",
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    candidate = f"scrypt${2**15}$8$1${salt.hex()}${digest.hex()}"

    assert service.verify_password("parol-123", candidate)
    assert not service.verify_password("parol-124", candidate)


# --- Валидация входа --------------------------------------------------------------


def test_fr_022_validation_error_does_not_echo_password(client: AppClient) -> None:
    """422 не повторяет присланный пароль: ни поля `input`, ни самого значения."""
    password = "секрет" * 200  # 1200 символов, больше max_length=1024

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": password},
    )

    assert response.status_code == 422
    assert password not in response.text
    assert '"input"' not in response.text
    detail = response.json()["detail"]
    assert detail
    assert all(set(error) == {"type", "loc", "msg"} for error in detail)


def test_fr_022_validation_error_omits_input_for_wrong_type(client: AppClient) -> None:
    """Неверный тип поля: 422 с полями type/loc/msg, без `input` и `ctx`."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": 123, "password": "секрет-123"},
    )

    assert response.status_code == 422
    assert '"input"' not in response.text
    assert '"ctx"' not in response.text
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}


def test_fr_022_validation_error_serializes_integer_loc() -> None:
    """`loc` с номером элемента массива (int) сериализуется в JSON числом."""
    error = RequestValidationError(
        [
            {
                "type": "int_parsing",
                "loc": ("body", "items", 0),
                "msg": "Input should be a valid integer",
                "input": "секрет-123",
            }
        ]
    )

    response = asyncio.run(validation_error_handler(None, error))  # type: ignore[arg-type]
    body = json.loads(response.body)

    assert body == {
        "detail": [
            {
                "type": "int_parsing",
                "loc": ["body", "items", 0],
                "msg": "Input should be a valid integer",
            }
        ]
    }
    assert "секрет-123" not in response.body.decode()


def test_fr_022_html_routes_are_not_in_rest_contract() -> None:
    """REST-контракт не содержит HTML-страниц: у них include_in_schema=False."""
    paths = app.openapi()["paths"]

    assert "/login" not in paths
    assert "/logout" not in paths
    assert "/api/v1/auth/login" in paths


# --- Сессия в БД ------------------------------------------------------------------


@pytest.mark.integration
def test_fr_022_expired_session_is_not_found_and_removed(db_session: Session) -> None:
    """Протухшая сессия пользователя не находится, а её строка удаляется."""
    user = _create_user(db_session, "expired@example.com", "пароль-123")
    token = service.create_session(db_session, user)
    db_session.execute(
        update(UserSession)
        .where(UserSession.token_hash == service.token_hash(token))
        .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    )
    db_session.commit()

    assert service.get_session_user(db_session, token) is None
    assert db_session.get(UserSession, service.token_hash(token)) is None


@pytest.mark.integration
def test_fr_022_api_login_returns_user_and_stores_token_hash(
    db_client: AppClient, db_session: Session
) -> None:
    """200 с пользователем, Set-Cookie с токеном; в sessions лежит только sha256."""
    _create_user(db_session, "api@example.com", "пароль-123")

    response = db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "api@example.com"
    assert body["role"] == "user"
    assert set(body) == {"id", "email", "role"}

    token = response.cookies.get(service.SESSION_COOKIE_NAME)
    assert token, "в ответе должен быть Set-Cookie с токеном сессии"
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME) == token

    set_cookie = response.headers["set-cookie"]
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie
    assert "Path=/" in set_cookie
    assert f"Max-Age={int(service.SESSION_LIFETIME.total_seconds())}" in set_cookie

    stored = db_session.get(UserSession, service.token_hash(token))
    assert stored is not None
    assert stored.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert len(stored.token_hash) == 64
    assert stored.token_hash != token, "открытый токен в БД не попадает"
    assert stored.expires_at > datetime.now(UTC)


@pytest.mark.integration
def test_fr_022_api_login_rejects_wrong_password(db_client: AppClient, db_session: Session) -> None:
    """Неверный пароль — 401, сессия не создаётся."""
    _create_user(db_session, "api@example.com", "пароль-123")

    response = db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "не тот"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Неверный email или пароль"}
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME) is None
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.integration
def test_fr_022_api_login_hides_unknown_email(db_client: AppClient) -> None:
    """Неизвестный email даёт тот же 401 и то же сообщение, что и неверный пароль."""
    response = db_client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "пароль-123"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Неверный email или пароль"}


@pytest.mark.integration
def test_fr_023_api_logout_closes_session_and_clears_cookie(
    db_client: AppClient, db_session: Session
) -> None:
    """204, cookie очищена, строки sessions больше нет."""
    _create_user(db_session, "api@example.com", "пароль-123")
    db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )
    token = db_client.cookies.get(service.SESSION_COOKIE_NAME)
    assert token

    response = db_client.post("/api/v1/auth/logout")

    assert response.status_code == 204
    assert response.content == b""
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME) is None
    assert db_session.get(UserSession, service.token_hash(token)) is None


@pytest.mark.integration
def test_fr_023_api_logout_without_session_is_idempotent(db_client: AppClient) -> None:
    """Без сессии выход тоже отвечает 204: повторный вызов безопасен."""
    response = db_client.post("/api/v1/auth/logout")

    assert response.status_code == 204


@pytest.mark.integration
def test_fr_023_api_logout_twice_is_safe(db_client: AppClient, db_session: Session) -> None:
    """Повторный выход после входа — тоже 204, и ничего не ломает."""
    _create_user(db_session, "api@example.com", "пароль-123")
    db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )

    first = db_client.post("/api/v1/auth/logout")
    second = db_client.post("/api/v1/auth/logout")

    assert first.status_code == 204
    assert second.status_code == 204
    assert db_session.scalar(select(func.count()).select_from(UserSession)) == 0


@pytest.mark.integration
def test_fr_022_login_after_logout_gives_new_token(
    db_client: AppClient, db_session: Session
) -> None:
    """Новый вход выдаёт другой токен, старой строки в sessions уже нет."""
    _create_user(db_session, "api@example.com", "пароль-123")
    db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )
    first_token = db_client.cookies.get(service.SESSION_COOKIE_NAME)
    assert first_token

    db_client.post("/api/v1/auth/logout")
    db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )
    second_token = db_client.cookies.get(service.SESSION_COOKIE_NAME)

    assert second_token
    assert second_token != first_token
    assert db_session.get(UserSession, service.token_hash(first_token)) is None
    assert db_session.get(UserSession, service.token_hash(second_token)) is not None


@pytest.mark.integration
def test_fr_023_anonymous_logout_keeps_session(db_client: AppClient, db_session: Session) -> None:
    """После clear_cookies запрос анонимный: 204, но строка сессии остаётся."""
    _create_user(db_session, "api@example.com", "пароль-123")
    db_client.post(
        "/api/v1/auth/login",
        json={"email": "api@example.com", "password": "пароль-123"},
    )
    token = db_client.cookies.get(service.SESSION_COOKIE_NAME)
    assert token

    db_client.clear_cookies()
    response = db_client.post("/api/v1/auth/logout")

    assert response.status_code == 204
    assert db_session.get(UserSession, service.token_hash(token)) is not None


# --- Серверный интерфейс ----------------------------------------------------------


def test_fr_022_login_page_shows_form(client: AppClient) -> None:
    """GET /login — 200, HTML с формой и русскими подписями."""
    response = client.get("/login")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text
    assert 'name="email"' in body
    assert 'name="password"' in body
    assert "Вход в Security Gate" in body
    assert "Пароль" in body


@pytest.mark.integration
def test_fr_022_login_form_redirects_after_success(
    db_client: AppClient, db_session: Session
) -> None:
    """POST /login — 303 на /projects и cookie сессии."""
    _create_user(db_session, "html@example.com", "пароль-123")

    response = db_client.post(
        "/login",
        data={"email": "html@example.com", "password": "пароль-123"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/projects"
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME)


@pytest.mark.integration
def test_fr_022_login_form_shows_error_for_wrong_password(
    db_client: AppClient, db_session: Session
) -> None:
    """POST /login с неверным паролем — 401, та же форма, введённый email сохранён."""
    _create_user(db_session, "html@example.com", "пароль-123")

    response = db_client.post(
        "/login",
        data={"email": "html@example.com", "password": "не тот"},
    )

    assert response.status_code == 401
    assert "Неверный email или пароль" in response.text
    assert 'value="html@example.com"' in response.text
    assert 'name="password"' in response.text
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME) is None


@pytest.mark.integration
def test_fr_023_logout_form_redirects_to_login(db_client: AppClient, db_session: Session) -> None:
    """POST /logout — 303 на /login, сессия закрыта."""
    _create_user(db_session, "html@example.com", "пароль-123")
    db_client.post(
        "/login",
        data={"email": "html@example.com", "password": "пароль-123"},
    )
    token = db_client.cookies.get(service.SESSION_COOKIE_NAME)
    assert token

    response = db_client.post("/logout")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert db_client.cookies.get(service.SESSION_COOKIE_NAME) is None
    assert db_session.get(UserSession, service.token_hash(token)) is None
