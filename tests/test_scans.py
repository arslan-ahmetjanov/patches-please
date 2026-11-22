"""Прогоны: приём, очередь, поллинг статуса (T-008, FR-001, FR-007, FR-019).

Быстрые тесты проверяют валидацию полей запуска и обвязку очереди: задача
ставится с идентификатором прогона. Жизненный цикл статусов и задача воркера —
в `tests/test_status.py` (T-009, FR-026). Интеграционные тесты идут через API
на тестовой базе с fake-очередью: Redis ради проверки постановки задачи не
нужен, `app.dependency_overrides` подменяет `get_scan_queue`.

Токен проекта — единственный ключ доступа к прогонам в T-008: cookie-сессия
операции не открывает, чужой прогон не отличается от несуществующего.
"""

import uuid
from collections.abc import Iterator

import pytest
from conftest import AppClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import service as auth_service
from app.auth.models import User
from app.main import app
from app.scans.models import Scan
from app.scans.queue import enqueue_scan, get_scan_queue, process_scan
from app.scans.router import (
    SCAN_NOT_FOUND_MESSAGE,
    TOKEN_REQUIRED_MESSAGE,
    Provider,
    ScanCreate,
)
from app.tokens import service as tokens_service

PASSWORD = "пароль-123"
# Полные хеши: SHA-1 у GitHub и GitLab по умолчанию, SHA-256 — у репозиториев нового типа.
SHA1_GITHUB = "a" * 40
SHA1_GITLAB = "b" * 40
SHA256_GITLAB = "c" * 64


class FakeQueue:
    """Подмена RQ: запоминает поставленные задачи, в Redis не ходит."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []
        self.options: list[dict[str, object]] = []

    def enqueue(self, func: object, scan_id: str, **options: object) -> None:
        self.calls.append((func, scan_id))
        self.options.append(options)


@pytest.fixture
def scan_queue() -> Iterator[FakeQueue]:
    """Очередь, в которую смотрит приложение: тест видит поставленные задачи."""
    fake = FakeQueue()
    app.dependency_overrides[get_scan_queue] = lambda: fake
    try:
        yield fake
    finally:
        app.dependency_overrides.pop(get_scan_queue, None)


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


def _create_token(client: AppClient, project_id: uuid.UUID) -> tuple[str, uuid.UUID]:
    """Открытое значение токена и его идентификатор (нужен для отзыва)."""
    response = client.post(f"/api/v1/projects/{project_id}/tokens", json={"name": "CI"})
    assert response.status_code == 201, response.text
    body = response.json()
    return body["token"], uuid.UUID(body["id"])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _scan_payload(
    commit_sha: str = SHA1_GITHUB,
    ref: str = "refs/heads/main",
    provider: str = "github",
) -> dict[str, str]:
    return {"commit_sha": commit_sha, "ref": ref, "provider": provider}


def _start_scan(
    client: AppClient,
    token: str,
    payload: dict[str, str] | None = None,
) -> dict:
    response = client.post("/api/v1/scans", json=payload or _scan_payload(), headers=_bearer(token))
    assert response.status_code == 202, response.text
    return response.json()


def _owner_with_token(
    client: AppClient,
    session: Session,
    slug: str,
    email: str = "owner@example.com",
) -> tuple[uuid.UUID, str, uuid.UUID]:
    """Проект, открытый токен и его id — минимум для запроса прогона."""
    _create_user(session, email)
    _login(client, email)
    project_id = _create_project(client, "Демо", slug)
    token, token_id = _create_token(client, project_id)
    return project_id, token, token_id


# --- Валидация полей запуска: быстро, без базы -----------------------------------


def test_fr_019_both_providers_are_accepted() -> None:
    """GitHub и GitLab проходят валидацию одинаково: отдельной логики нет."""
    github = ScanCreate(commit_sha=SHA1_GITHUB, ref="main", provider="github")
    gitlab = ScanCreate(commit_sha=SHA1_GITLAB, ref="main", provider="gitlab")

    assert github.provider == Provider.GITHUB
    assert gitlab.provider == Provider.GITLAB


@pytest.mark.parametrize("provider", ["bitbucket", "GitHub", ""])
def test_fr_019_unknown_provider_is_rejected(provider: str) -> None:
    with pytest.raises(ValidationError):
        ScanCreate(commit_sha=SHA1_GITHUB, ref="main", provider=provider)


def test_fr_001_commit_sha_accepts_full_sha1_and_sha256() -> None:
    sha1 = ScanCreate(commit_sha=SHA1_GITHUB, ref="main", provider="github")
    sha256 = ScanCreate(commit_sha=SHA256_GITLAB, ref="main", provider="gitlab")

    assert sha1.commit_sha == SHA1_GITHUB
    assert sha256.commit_sha == SHA256_GITLAB


@pytest.mark.parametrize(
    "commit_sha",
    [
        "a" * 7,
        "a" * 39,
        "a" * 41,
        "a" * 63,
        "a" * 65,
        "A" * 40,
        "z" * 40,
    ],
)
def test_fr_001_short_uppercase_and_non_hex_commit_sha_are_rejected(commit_sha: str) -> None:
    """Сокращённый хеш неоднозначен, а дедупликация идёт по точному значению."""
    with pytest.raises(ValidationError):
        ScanCreate(commit_sha=commit_sha, ref="main", provider="github")


def test_fr_001_ref_is_required_and_has_no_whitespace() -> None:
    assert ScanCreate(commit_sha=SHA1_GITHUB, ref="  main  ", provider="github").ref == "main"
    assert ScanCreate(commit_sha=SHA1_GITHUB, ref="refs/pull/1/head", provider="github").ref
    for ref in ("", "   ", "refs/heads/my branch"):
        with pytest.raises(ValidationError):
            ScanCreate(commit_sha=SHA1_GITHUB, ref=ref, provider="github")
    with pytest.raises(ValidationError):
        ScanCreate(commit_sha=SHA1_GITHUB, ref="r" * 256, provider="github")


# --- Очередь: быстро, без базы ---------------------------------------------------


def test_fr_001_enqueue_passes_scan_id_as_string() -> None:
    """Задача уходит с идентификатором-строкой: так она переживает сериализацию."""
    queue = FakeQueue()
    scan_id = uuid.uuid4()

    enqueue_scan(queue, scan_id)

    assert queue.calls == [(process_scan, str(scan_id))]


# --- API: создание прогона -------------------------------------------------------


@pytest.mark.integration
def test_fr_001_post_creates_queued_scan_and_enqueues(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """202 создаёт строку `queued`, ставит задачу и отдаёт объект прогона."""
    project_id, token, _ = _owner_with_token(db_client, db_session, "demo")

    ci = AppClient(app)
    body = _start_scan(ci, token)

    assert set(body) == {
        "id",
        "status",
        "commit_sha",
        "ref",
        "provider",
        "created_at",
        "verdict",
    }
    assert body["status"] == "queued"
    assert body["verdict"] is None
    assert body["commit_sha"] == SHA1_GITHUB
    assert body["ref"] == "refs/heads/main"
    assert body["provider"] == "github"
    assert body["created_at"]

    stored = db_session.get(Scan, uuid.UUID(body["id"]))
    assert stored is not None
    assert stored.project_id == project_id
    assert stored.status == "queued"
    assert stored.started_at is None
    assert stored.finished_at is None
    assert stored.verdict is None
    assert stored.error is None
    assert stored.timings is None
    assert scan_queue.calls == [(process_scan, body["id"])]


@pytest.mark.integration
def test_fr_019_two_providers_return_same_structure(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """GitHub и GitLab дают прогоны одной структуры: отличается только провайдер."""
    _, token, _ = _owner_with_token(db_client, db_session, "demo")

    ci = AppClient(app)
    github = _start_scan(ci, token, _scan_payload(SHA1_GITHUB, provider="github"))
    gitlab = _start_scan(ci, token, _scan_payload(SHA256_GITLAB, provider="gitlab"))

    assert set(github) == set(gitlab)
    assert github["provider"] == "github"
    assert gitlab["provider"] == "gitlab"
    assert github["id"] != gitlab["id"]
    assert github["status"] == gitlab["status"] == "queued"
    assert len(scan_queue.calls) == 2

    providers = db_session.scalars(select(Scan.provider).order_by(Scan.commit_sha)).all()
    assert sorted(providers) == ["github", "gitlab"]


@pytest.mark.integration
def test_fr_001_repeat_post_returns_existing_scan_without_second_job(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """Повтор на тот же коммит — 202 с тем же прогоном, без второй строки и задачи."""
    project_id, token, _ = _owner_with_token(db_client, db_session, "demo")

    ci = AppClient(app)
    first = _start_scan(ci, token)
    second = _start_scan(ci, token)

    assert first["id"] == second["id"]
    assert len(scan_queue.calls) == 1
    count = db_session.scalar(
        select(func.count()).select_from(Scan).where(Scan.project_id == project_id)
    )
    assert count == 1


@pytest.mark.integration
def test_fr_001_same_commit_in_another_project_is_a_separate_scan(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """Дедупликация идёт в границах проекта: чужой проект на коммит не влияет."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    first_project = _create_project(db_client, "Первый", "first")
    second_project = _create_project(db_client, "Второй", "second")
    first_token, _ = _create_token(db_client, first_project)
    second_token, _ = _create_token(db_client, second_project)

    ci = AppClient(app)
    first = _start_scan(ci, first_token)
    second = _start_scan(ci, second_token)

    assert first["id"] != second["id"]
    assert len(scan_queue.calls) == 2


# --- API: поллинг статуса --------------------------------------------------------


@pytest.mark.integration
def test_fr_007_get_returns_scan_fields(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """GET отдаёт статус, коммит, ветку, провайдера, время создания и вердикт."""
    _, token, _ = _owner_with_token(db_client, db_session, "demo")

    ci = AppClient(app)
    created = _start_scan(ci, token)
    response = ci.get(f"/api/v1/scans/{created['id']}", headers=_bearer(token))

    assert response.status_code == 200, response.text
    assert response.json() == created


@pytest.mark.integration
def test_fr_007_unknown_scan_returns_404(db_client: AppClient, db_session: Session) -> None:
    _, token, _ = _owner_with_token(db_client, db_session, "demo")

    response = AppClient(app).get(f"/api/v1/scans/{uuid.uuid4()}", headers=_bearer(token))

    assert response.status_code == 404
    assert response.json() == {"detail": SCAN_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_007_scan_of_another_project_is_hidden_with_404(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """Токен проекта А не читает прогон проекта Б: 404, как у несуществующего."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    first_project = _create_project(db_client, "Первый", "first")
    second_project = _create_project(db_client, "Второй", "second")
    first_token, _ = _create_token(db_client, first_project)
    second_token, _ = _create_token(db_client, second_project)

    ci = AppClient(app)
    foreign = _start_scan(ci, second_token)
    response = ci.get(f"/api/v1/scans/{foreign['id']}", headers=_bearer(first_token))

    assert response.status_code == 404
    assert response.json() == {"detail": SCAN_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_007_malformed_scan_id_returns_422(db_client: AppClient, db_session: Session) -> None:
    _, token, _ = _owner_with_token(db_client, db_session, "demo")

    response = AppClient(app).get("/api/v1/scans/not-a-uuid", headers=_bearer(token))

    assert response.status_code == 422


# --- API: доступ ------------------------------------------------------------------


@pytest.mark.integration
def test_fr_001_missing_token_returns_401(
    db_client: AppClient, db_session: Session, scan_queue: FakeQueue
) -> None:
    """Без заголовка обе операции отвечают 401 в формате ErrorResponse."""
    _, token, _ = _owner_with_token(db_client, db_session, "demo")
    ci = AppClient(app)
    created = _start_scan(ci, token)

    started = ci.post("/api/v1/scans", json=_scan_payload())
    polled = ci.get(f"/api/v1/scans/{created['id']}")

    for response in (started, polled):
        assert response.status_code == 401
        assert response.json() == {"detail": TOKEN_REQUIRED_MESSAGE}
        assert response.headers["www-authenticate"].lower() == "bearer"


@pytest.mark.integration
def test_fr_001_unknown_token_returns_401(db_client: AppClient, db_session: Session) -> None:
    """Неизвестное значение токена не отличается от отсутствующего."""
    response = AppClient(app).post(
        "/api/v1/scans", json=_scan_payload(), headers=_bearer("sg_unknown_token")
    )

    assert response.status_code == 401
    assert response.json() == {"detail": TOKEN_REQUIRED_MESSAGE}


@pytest.mark.integration
def test_fr_001_revoked_token_returns_401(db_client: AppClient, db_session: Session) -> None:
    """Отозванный токен прогоны не запускает: проверка идёт через `verify_token`."""
    project_id, token, token_id = _owner_with_token(db_client, db_session, "demo")
    assert tokens_service.revoke_token(db_session, project_id, token_id)

    response = AppClient(app).post("/api/v1/scans", json=_scan_payload(), headers=_bearer(token))

    assert response.status_code == 401
    assert response.json() == {"detail": TOKEN_REQUIRED_MESSAGE}


@pytest.mark.integration
@pytest.mark.parametrize("authorization", ["Basic c2ctdG9rZW4=", "Bearer", "Bearer   "])
def test_fr_001_malformed_authorization_returns_401(
    db_client: AppClient, db_session: Session, authorization: str
) -> None:
    response = AppClient(app).post(
        "/api/v1/scans", json=_scan_payload(), headers={"Authorization": authorization}
    )

    assert response.status_code == 401
    assert response.json() == {"detail": TOKEN_REQUIRED_MESSAGE}


@pytest.mark.integration
def test_fr_001_cookie_session_does_not_open_scans(
    db_client: AppClient, db_session: Session
) -> None:
    """Сессия интерфейса в T-008 прогоны не открывает: нужен токен проекта."""
    _owner_with_token(db_client, db_session, "demo")

    response = db_client.post("/api/v1/scans", json=_scan_payload())

    assert response.status_code == 401
    assert response.json() == {"detail": TOKEN_REQUIRED_MESSAGE}


@pytest.mark.integration
@pytest.mark.parametrize(
    "payload",
    [
        {"commit_sha": SHA1_GITHUB, "ref": "main", "provider": "bitbucket"},
        {"commit_sha": "a" * 7, "ref": "main", "provider": "github"},
        {"commit_sha": SHA1_GITHUB, "ref": "  ", "provider": "github"},
        {"commit_sha": SHA1_GITHUB, "provider": "github"},
    ],
)
def test_fr_001_invalid_payload_returns_422_without_input_values(
    db_client: AppClient, db_session: Session, payload: dict[str, str]
) -> None:
    """Неверные поля отсекаются на границе API, присланные значения не возвращаются."""
    _, token, _ = _owner_with_token(db_client, db_session, "demo")

    response = AppClient(app).post("/api/v1/scans", json=payload, headers=_bearer(token))

    assert response.status_code == 422
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}
    assert "bitbucket" not in response.text
