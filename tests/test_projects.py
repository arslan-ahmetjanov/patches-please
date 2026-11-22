"""Проекты: создание, список, изоляция по членству (T-005, FR-017).

Быстрые тесты проверяют модель создания без базы: формат slug, обязательность
полей, значения по умолчанию. Интеграционные — API и HTML на тестовой базе:
создатель становится участником, чужой проект не виден, дубль slug даёт 409,
без сессии закрыты оба входа.
"""

import uuid

import pytest
from conftest import AppClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.auth.models import User
from patches_please.main import app
from patches_please.projects.models import OWNER_ROLE, ProjectMember
from patches_please.projects.router import SLUG_TAKEN_MESSAGE, ProjectCreate

PASSWORD = "пароль-123"


def _create_user(session: Session, email: str) -> User:
    """Заводит учётную запись: регистрации нет, первый пользователь — из теста."""
    return service.create_user(session, email, PASSWORD)


def _login(client: AppClient, email: str) -> None:
    """Вход через API: cookie остаётся в клиенте и уходит со следующими запросами."""
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text


def _create_project(client: AppClient, name: str, slug: str) -> uuid.UUID:
    response = client.post("/api/v1/projects", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


# --- Валидация полей: быстро, без базы -------------------------------------------


@pytest.mark.parametrize("slug", ["ab", "demo", "demo-project", "a1", "x" * 100])
def test_fr_017_slug_accepts_valid_format(slug: str) -> None:
    """Строчные латинские буквы, цифры и дефис; от 2 до 100 символов."""
    assert ProjectCreate(name="Проект", slug=slug).slug == slug


@pytest.mark.parametrize(
    "slug",
    [
        "",
        "a",
        "-demo",
        "Demo",
        "demo_project",
        "демо",
        "demo project",
        "demo/path",
        "x" * 101,
    ],
)
def test_fr_017_slug_rejects_invalid_format(slug: str) -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(name="Проект", slug=slug)


def test_fr_017_name_and_slug_are_stripped() -> None:
    """Пробелы по краям не попадают в базу и не ломают проверку формата."""
    payload = ProjectCreate(name="  Демо  ", slug="  demo  ")

    assert payload.name == "Демо"
    assert payload.slug == "demo"


def test_fr_017_name_cannot_be_blank() -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(name="   ", slug="demo")


def test_fr_017_name_is_limited_to_200_chars() -> None:
    assert ProjectCreate(name="x" * 200, slug="demo").name == "x" * 200
    with pytest.raises(ValidationError):
        ProjectCreate(name="x" * 201, slug="demo")


def test_fr_017_defaults_fill_branch_and_leave_repo_url_empty() -> None:
    payload = ProjectCreate(name="Демо", slug="demo")

    assert payload.default_branch == "main"
    assert payload.repo_url is None


def test_fr_017_blank_repo_url_becomes_none() -> None:
    """Пустое поле формы — это отсутствие адреса, а не пустая строка в базе."""
    assert ProjectCreate(name="Демо", slug="demo", repo_url="   ").repo_url is None
    assert (
        ProjectCreate(name="Демо", slug="demo", repo_url=" https://github.com/a/b ").repo_url
        == "https://github.com/a/b"
    )


def test_fr_017_default_branch_cannot_be_blank() -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(name="Демо", slug="demo", default_branch="   ")


# --- API: создание и список ------------------------------------------------------


@pytest.mark.integration
def test_fr_017_create_project_returns_201_and_owner_membership(
    db_client: AppClient, db_session: Session
) -> None:
    """Создатель сразу становится участником с ролью `owner`."""
    user = _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")

    response = db_client.post(
        "/api/v1/projects",
        json={"name": "Демо", "slug": "demo", "repo_url": "https://github.com/a/b"},
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "Демо"
    assert body["slug"] == "demo"
    assert body["repo_url"] == "https://github.com/a/b"
    assert body["default_branch"] == "main"
    assert body["created_at"]

    membership = db_session.scalar(
        select(ProjectMember).where(ProjectMember.project_id == uuid.UUID(body["id"]))
    )
    assert membership is not None
    assert membership.user_id == user.id
    assert membership.role == OWNER_ROLE


@pytest.mark.integration
def test_fr_017_list_does_not_show_foreign_projects(
    db_client: AppClient, db_session: Session
) -> None:
    """Пользователь А видит свой проект и не видит проект пользователя Б."""
    _create_user(db_session, "a@example.com")
    _create_user(db_session, "b@example.com")
    _login(db_client, "a@example.com")
    _create_project(db_client, "Проект А", "project-a")

    other = AppClient(app)
    _login(other, "b@example.com")
    _create_project(other, "Проект Б", "project-b")

    response = db_client.get("/api/v1/projects")

    assert response.status_code == 200
    assert [project["slug"] for project in response.json()] == ["project-a"]


@pytest.mark.integration
def test_fr_017_list_is_empty_for_new_user(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "new@example.com")
    _login(db_client, "new@example.com")

    response = db_client.get("/api/v1/projects")

    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.integration
def test_fr_017_duplicate_slug_returns_409_without_new_project(
    db_client: AppClient, db_session: Session
) -> None:
    """Занятый slug даёт 409, а второй пользователь не получает ни проекта, ни членства."""
    _create_user(db_session, "a@example.com")
    _create_user(db_session, "b@example.com")
    _login(db_client, "a@example.com")
    _create_project(db_client, "Проект А", "shared")

    other = AppClient(app)
    _login(other, "b@example.com")
    response = other.post("/api/v1/projects", json={"name": "Проект Б", "slug": "shared"})

    assert response.status_code == 409
    assert response.json() == {"detail": SLUG_TAKEN_MESSAGE}
    assert other.get("/api/v1/projects").json() == []


@pytest.mark.integration
def test_fr_017_api_requires_session(db_client: AppClient) -> None:
    """Без cookie оба метода отвечают 401, а не списком и не 422."""
    assert db_client.get("/api/v1/projects").status_code == 401
    assert db_client.get("/api/v1/projects").json() == {"detail": "Требуется вход"}

    created = db_client.post("/api/v1/projects", json={"name": "Демо", "slug": "demo"})
    assert created.status_code == 401


# --- HTML: страница проектов -----------------------------------------------------


@pytest.mark.integration
def test_fr_017_html_requires_session(db_client: AppClient) -> None:
    response = db_client.get("/projects")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.integration
def test_fr_017_html_page_shows_only_own_projects(
    db_client: AppClient, db_session: Session
) -> None:
    _create_user(db_session, "a@example.com")
    _create_user(db_session, "b@example.com")
    _login(db_client, "a@example.com")
    _create_project(db_client, "Проект А", "project-a")

    other = AppClient(app)
    _login(other, "b@example.com")
    _create_project(other, "Проект Б", "project-b")

    page = db_client.get("/projects")

    assert page.status_code == 200
    assert "Проект А" in page.text
    assert "project-a" in page.text
    assert "Проект Б" not in page.text
    assert "project-b" not in page.text


@pytest.mark.integration
def test_fr_017_html_create_redirects_to_list(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "a@example.com")
    _login(db_client, "a@example.com")

    response = db_client.post(
        "/projects",
        data={"name": "Новый", "slug": "new-one", "repo_url": "", "default_branch": "main"},
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/projects"
    page = db_client.get("/projects")
    assert "Новый" in page.text
    assert "new-one" in page.text


@pytest.mark.integration
def test_fr_017_html_duplicate_slug_keeps_form_values(
    db_client: AppClient, db_session: Session
) -> None:
    _create_user(db_session, "a@example.com")
    _login(db_client, "a@example.com")
    _create_project(db_client, "Проект А", "shared")

    response = db_client.post(
        "/projects",
        data={"name": "Второй", "slug": "shared", "repo_url": "", "default_branch": "main"},
    )

    assert response.status_code == 409
    assert SLUG_TAKEN_MESSAGE in response.text
    assert 'value="Второй"' in response.text


@pytest.mark.integration
def test_fr_017_html_invalid_slug_shows_message(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "a@example.com")
    _login(db_client, "a@example.com")

    response = db_client.post(
        "/projects",
        data={"name": "Проект", "slug": "Bad Slug", "repo_url": "", "default_branch": "main"},
    )

    assert response.status_code == 400
    assert "Проверьте поля" in response.text
    assert db_client.get("/api/v1/projects").json() == []
