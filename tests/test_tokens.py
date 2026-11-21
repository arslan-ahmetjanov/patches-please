"""Токены проектов: создание, одноразовый показ, список, отзыв (T-006).

Быстрые тесты проверяют формат токена, детерминизм хеша и валидацию названия
без базы. Интеграционные — API на тестовой базе: открытое значение приходит
только в ответе 201, в `project_tokens` лежит SHA-256, список значение не
отдаёт, отозванный токен не проходит `verify_token`, чужие проекты закрыты.

Номера тестов ссылаются на FR-024 и FR-025 из `delta-002-tokens.md`.
"""

import hashlib
import re
import uuid
from datetime import UTC, datetime

import pytest
from conftest import AppClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import service as auth_service
from app.auth.models import User
from app.main import app
from app.projects.models import MEMBER_ROLE, ProjectMember
from app.tokens import service
from app.tokens.models import ProjectToken
from app.tokens.router import (
    FORBIDDEN_MESSAGE,
    PROJECT_NOT_FOUND_MESSAGE,
    TOKEN_NOT_FOUND_MESSAGE,
    TokenCreate,
)

PASSWORD = "пароль-123"


def _create_user(session: Session, email: str) -> User:
    """Заводит учётную запись: регистрации нет, пользователи — из тестов."""
    return auth_service.create_user(session, email, PASSWORD)


def _login(client: AppClient, email: str) -> None:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text


def _create_project(client: AppClient, name: str, slug: str) -> uuid.UUID:
    response = client.post("/api/v1/projects", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _add_member(session: Session, project_id: uuid.UUID, user: User, role: str) -> None:
    """Добавляет участника напрямую: управления участниками в API ещё нет (T-025)."""
    session.add(ProjectMember(project_id=project_id, user_id=user.id, role=role))
    session.commit()


def _create_token(client: AppClient, project_id: uuid.UUID, name: str = "GitHub Actions") -> dict:
    response = client.post(f"/api/v1/projects/{project_id}/tokens", json={"name": name})
    assert response.status_code == 201, response.text
    return response.json()


# --- Формат токена и хеш: быстро, без базы ---------------------------------------


def test_fr_024_token_has_prefix_and_expected_length() -> None:
    """`sg_` + token_urlsafe(32): 3 + 43 символа."""
    token = service.generate_token()

    assert token.startswith("sg_")
    assert len(token) == len("sg_") + 43
    assert re.fullmatch(r"sg_[A-Za-z0-9_-]{43}", token)


def test_fr_024_generated_tokens_are_unique() -> None:
    """Случайная часть не повторяется: сто токенов — сто разных значений."""
    tokens = {service.generate_token() for _ in range(100)}

    assert len(tokens) == 100


def test_fr_024_hash_is_sha256_hex_without_salt() -> None:
    """В базе ровно SHA-256 в hex: хеш детерминирован и совпадает с hashlib."""
    token = "sg_проверка"

    digest = auth_service.token_hash(token)

    assert digest == hashlib.sha256(token.encode()).hexdigest()
    assert len(digest) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", digest)


def test_fr_024_different_tokens_have_different_hashes() -> None:
    assert auth_service.token_hash(service.generate_token()) != auth_service.token_hash(
        service.generate_token()
    )


def test_fr_024_name_is_required() -> None:
    with pytest.raises(ValidationError):
        TokenCreate(name="")


def test_fr_024_name_cannot_be_blank() -> None:
    with pytest.raises(ValidationError):
        TokenCreate(name="   ")


def test_fr_024_name_is_stripped_and_limited_to_100_chars() -> None:
    assert TokenCreate(name="  CI  ").name == "CI"
    assert TokenCreate(name="x" * 100).name == "x" * 100
    with pytest.raises(ValidationError):
        TokenCreate(name="x" * 101)


# --- API: создание и одноразовый показ -------------------------------------------


@pytest.mark.integration
def test_fr_024_create_returns_token_once_and_stores_only_hash(
    db_client: AppClient, db_session: Session
) -> None:
    """201 отдаёт открытое значение, а в `project_tokens` попадает только его хеш."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    body = _create_token(db_client, project_id, "GitHub Actions")

    assert set(body) == {"id", "name", "token", "created_at"}
    assert body["token"].startswith("sg_")
    assert body["name"] == "GitHub Actions"
    assert uuid.UUID(body["id"]) and body["created_at"]

    stored = db_session.scalar(select(ProjectToken).where(ProjectToken.project_id == project_id))
    assert stored is not None
    assert stored.id == uuid.UUID(body["id"])
    assert stored.name == "GitHub Actions"
    assert stored.token_hash == auth_service.token_hash(body["token"])
    assert len(stored.token_hash) == 64
    # Открытого значения в строке нет ни в одном поле.
    assert body["token"] not in stored.name
    assert body["token"] not in stored.token_hash
    assert stored.revoked_at is None
    assert stored.last_used_at is None


@pytest.mark.integration
def test_fr_024_list_never_returns_open_token(db_client: AppClient, db_session: Session) -> None:
    """Список отдаёт метаданные: открытое значение после создания не восстановить."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id, "GitHub Actions")

    response = db_client.get(f"/api/v1/projects/{project_id}/tokens")

    assert response.status_code == 200, response.text
    assert created["token"] not in response.text
    tokens = response.json()
    assert len(tokens) == 1
    assert set(tokens[0]) == {"id", "name", "created_at", "last_used_at", "revoked_at"}
    assert tokens[0]["id"] == created["id"]
    assert tokens[0]["revoked_at"] is None


@pytest.mark.integration
def test_fr_024_list_is_empty_for_project_without_tokens(
    db_client: AppClient, db_session: Session
) -> None:
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    response = db_client.get(f"/api/v1/projects/{project_id}/tokens")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.integration
def test_fr_024_list_orders_newest_first_and_by_name_on_equal_time(
    db_client: AppClient, db_session: Session
) -> None:
    """Порядок списка: свежие сверху, при равном времени создания — по названию."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    same_time = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
    older = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    db_session.add_all(
        [
            ProjectToken(
                project_id=project_id,
                name="Бета",
                token_hash=auth_service.token_hash("sg_бета"),
                created_at=same_time,
            ),
            ProjectToken(
                project_id=project_id,
                name="Альфа",
                token_hash=auth_service.token_hash("sg_альфа"),
                created_at=same_time,
            ),
            ProjectToken(
                project_id=project_id,
                name="Старый",
                token_hash=auth_service.token_hash("sg_старый"),
                created_at=older,
            ),
        ]
    )
    db_session.commit()

    listed = db_client.get(f"/api/v1/projects/{project_id}/tokens").json()

    assert [item["name"] for item in listed] == ["Альфа", "Бета", "Старый"]


@pytest.mark.parametrize("name", ["", "   ", "x" * 101])
@pytest.mark.integration
def test_fr_024_invalid_name_returns_422_without_input_values(
    db_client: AppClient, db_session: Session, name: str
) -> None:
    """Пустое, пробельное и слишком длинное название — 422 без присланного значения."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    response = db_client.post(f"/api/v1/projects/{project_id}/tokens", json={"name": name})

    assert response.status_code == 422
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}
    if name.strip():
        assert name not in response.text


# --- API: права ------------------------------------------------------------------


@pytest.mark.integration
def test_fr_024_requires_session(db_client: AppClient, db_session: Session) -> None:
    """Без cookie все три метода отвечают 401, а не 404 и не списком."""
    _create_user(db_session, "owner@example.com")
    client = AppClient(app)
    _login(client, "owner@example.com")
    project_id = _create_project(client, "Демо", "demo")
    created = _create_token(client, project_id)

    assert db_client.get(f"/api/v1/projects/{project_id}/tokens").status_code == 401
    assert (
        db_client.post(f"/api/v1/projects/{project_id}/tokens", json={"name": "CI"}).status_code
        == 401
    )
    assert (
        db_client.delete(f"/api/v1/projects/{project_id}/tokens/{created['id']}").status_code == 401
    )


@pytest.mark.integration
def test_fr_024_member_sees_list_but_cannot_create_or_revoke(
    db_client: AppClient, db_session: Session
) -> None:
    """`member` видит метаданные, но запись — только у `owner`: 403."""
    _create_user(db_session, "owner@example.com")
    member = _create_user(db_session, "member@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id)
    _add_member(db_session, project_id, member, MEMBER_ROLE)

    member_client = AppClient(app)
    _login(member_client, "member@example.com")

    listed = member_client.get(f"/api/v1/projects/{project_id}/tokens")
    assert listed.status_code == 200
    assert [token["id"] for token in listed.json()] == [created["id"]]

    created_response = member_client.post(
        f"/api/v1/projects/{project_id}/tokens", json={"name": "Свой"}
    )
    assert created_response.status_code == 403
    assert created_response.json() == {"detail": FORBIDDEN_MESSAGE}

    revoked = member_client.delete(f"/api/v1/projects/{project_id}/tokens/{created['id']}")
    assert revoked.status_code == 403
    # Токен владельца не пострадал: отзыв не прошёл.
    assert db_session.get(ProjectToken, uuid.UUID(created["id"])).revoked_at is None


@pytest.mark.integration
def test_fr_024_foreign_project_is_hidden_with_404(
    db_client: AppClient, db_session: Session
) -> None:
    """Посторонний получает 404 на проект, токены и отзыв: чужих данных не видно."""
    _create_user(db_session, "owner@example.com")
    _create_user(db_session, "stranger@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id)

    stranger = AppClient(app)
    _login(stranger, "stranger@example.com")

    listed = stranger.get(f"/api/v1/projects/{project_id}/tokens")
    assert listed.status_code == 404
    assert listed.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    created_response = stranger.post(
        f"/api/v1/projects/{project_id}/tokens", json={"name": "Чужой"}
    )
    assert created_response.status_code == 404
    assert created_response.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    revoked = stranger.delete(f"/api/v1/projects/{project_id}/tokens/{created['id']}")
    assert revoked.status_code == 404
    assert revoked.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_024_unknown_project_returns_404(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    missing = uuid.uuid4()

    response = db_client.get(f"/api/v1/projects/{missing}/tokens")

    assert response.status_code == 404
    assert response.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_024_malformed_project_id_returns_422(db_client: AppClient, db_session: Session) -> None:
    """В пути UUID: у вошедшего пользователя строка другого вида отсекается валидацией."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")

    response = db_client.get("/api/v1/projects/not-a-uuid/tokens")

    assert response.status_code == 422


# --- API: отзыв ------------------------------------------------------------------


@pytest.mark.integration
def test_fr_025_revoke_marks_token_and_verify_returns_none(
    db_client: AppClient, db_session: Session
) -> None:
    """Отзыв заполняет `revoked_at`, строка остаётся, `verify_token` молчит."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id)
    assert service.verify_token(db_session, created["token"]) is not None

    response = db_client.delete(f"/api/v1/projects/{project_id}/tokens/{created['id']}")

    assert response.status_code == 204
    assert response.text == ""
    stored = db_session.get(ProjectToken, uuid.UUID(created["id"]))
    assert stored is not None
    assert stored.revoked_at is not None
    assert service.verify_token(db_session, created["token"]) is None
    # Отозванный токен остаётся в списке с временем отзыва.
    listed = db_client.get(f"/api/v1/projects/{project_id}/tokens").json()
    assert listed[0]["revoked_at"] is not None


@pytest.mark.integration
def test_fr_025_repeat_revoke_is_204_and_keeps_first_time(
    db_client: AppClient, db_session: Session
) -> None:
    """Повторный отзыв идемпотентен и не переписывает время первого отзыва."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id)
    url = f"/api/v1/projects/{project_id}/tokens/{created['id']}"

    assert db_client.delete(url).status_code == 204
    first_revoked_at = db_session.get(ProjectToken, uuid.UUID(created["id"])).revoked_at
    assert db_client.delete(url).status_code == 204
    db_session.expire_all()

    assert db_session.get(ProjectToken, uuid.UUID(created["id"])).revoked_at == first_revoked_at


@pytest.mark.integration
def test_fr_025_unknown_token_returns_404(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    response = db_client.delete(f"/api/v1/projects/{project_id}/tokens/{uuid.uuid4()}")

    assert response.status_code == 404
    assert response.json() == {"detail": TOKEN_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_025_token_of_another_project_returns_404(
    db_client: AppClient, db_session: Session
) -> None:
    """Токен чужого проекта через свой project_id не отозвать: 404."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    first_project = _create_project(db_client, "Первый", "first")
    second_project = _create_project(db_client, "Второй", "second")
    created = _create_token(db_client, first_project)

    response = db_client.delete(f"/api/v1/projects/{second_project}/tokens/{created['id']}")

    assert response.status_code == 404
    assert response.json() == {"detail": TOKEN_NOT_FOUND_MESSAGE}
    assert db_session.get(ProjectToken, uuid.UUID(created["id"])).revoked_at is None


# --- Сервис: проверка токена -----------------------------------------------------


@pytest.mark.integration
def test_fr_024_verify_token_updates_last_used_at(
    db_client: AppClient, db_session: Session
) -> None:
    """Успешная проверка отмечает использование; неизвестный токен — `None`."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    created = _create_token(db_client, project_id)

    stored = service.verify_token(db_session, created["token"])

    assert stored is not None
    assert stored.last_used_at is not None
    assert service.verify_token(db_session, "sg_неизвестный") is None
