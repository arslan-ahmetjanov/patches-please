"""Проекты: список, создание и изоляция по членству (T-005, FR-017).

API (`/api/v1/projects`) отвечает JSON и описан в `contracts/openapi.yaml`.
Страницы (`/projects`) рендерятся Jinja2 и в контракт не входят. Список в обоих
случаях один и тот же: `project_members` решает, что видит пользователь.
"""

import uuid
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Final

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, StringConstraints, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.dependencies import ApiUser, DbSession, HtmlUser
from app.auth.models import User
from app.auth.router import ErrorResponse
from app.projects.models import OWNER_ROLE, Project, ProjectMember

# Шаблоны лежат в корне репозитория, рядом с app/: отсюда это два уровня вверх.
TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Полное совпадение: pydantic проверяет шаблон поиском, поэтому якоря обязательны.
SLUG_PATTERN: Final = r"^[a-z0-9][a-z0-9-]{1,99}$"

ProjectName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
ProjectSlug = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=2, max_length=100, pattern=SLUG_PATTERN),
]
BranchName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]

SLUG_TAKEN_MESSAGE: Final = "Проект с таким slug уже существует"
FORM_INVALID_MESSAGE: Final = (
    "Проверьте поля: название и slug обязательны, slug — строчные латинские буквы, цифры и дефис."
)


class ProjectCreate(BaseModel):
    """Данные создания проекта. Slug вводится вручную, repo_url необязателен."""

    name: ProjectName
    slug: ProjectSlug
    repo_url: str | None = Field(default=None, max_length=2048)
    default_branch: BranchName = "main"

    @field_validator("repo_url", mode="after")
    @classmethod
    def _blank_repo_url_to_none(cls, value: str | None) -> str | None:
        """Пустое поле формы приходит строкой: в базе храним NULL, а не `''`."""
        if value is None:
            return None
        stripped = value.strip()
        return stripped or None


class ProjectResponse(BaseModel):
    """Проект в ответе API."""

    id: uuid.UUID
    name: str
    slug: str
    repo_url: str | None
    default_branch: str
    created_at: datetime

    @classmethod
    def from_model(cls, project: Project) -> "ProjectResponse":
        return cls(
            id=project.id,
            name=project.name,
            slug=project.slug,
            repo_url=project.repo_url,
            default_branch=project.default_branch,
            created_at=project.created_at,
        )


class ProjectSlugTakenError(Exception):
    """slug уже занят: сработал уникальный индекс `projects.slug`."""


def list_user_projects(session: Session, user_id: uuid.UUID) -> list[Project]:
    """Проекты, где пользователь участник. Свежие сверху, при равенстве — по slug."""
    statement = (
        select(Project)
        .join(ProjectMember, ProjectMember.project_id == Project.id)
        .where(ProjectMember.user_id == user_id)
        .order_by(Project.created_at.desc(), Project.slug)
    )
    return list(session.scalars(statement))


def create_project(session: Session, payload: ProjectCreate, user: User) -> Project:
    """Создаёт проект и членство создателя одной транзакцией.

    Создатель получает роль `owner`: без строки членства проект не виден никому,
    поэтому обе записи пишутся вместе. Занятый slug отсекается запросом до вставки,
    а уникальный индекс остаётся страховкой от гонки двух одновременных запросов.
    """
    if session.scalar(select(Project.id).where(Project.slug == payload.slug)) is not None:
        raise ProjectSlugTakenError(payload.slug)

    project = Project(
        name=payload.name,
        slug=payload.slug,
        repo_url=payload.repo_url,
        default_branch=payload.default_branch,
    )
    try:
        session.add(project)
        # id выдаёт PostgreSQL: до flush его нет, а он нужен строке членства.
        session.flush()
        session.add(ProjectMember(project_id=project.id, user_id=user.id, role=OWNER_ROLE))
        session.commit()
    except IntegrityError as error:
        # Гонка: slug заняли между проверкой и вставкой. Пользователь уже существует,
        # а project_id создан в этой транзакции, поэтому иное нарушение здесь маловероятно.
        session.rollback()
        raise ProjectSlugTakenError(payload.slug) from error
    session.refresh(project)
    return project


api_router = APIRouter(prefix="/api/v1/projects", tags=["проекты"])
html_router = APIRouter(include_in_schema=False)


@api_router.get(
    "",
    summary="Проекты текущего пользователя",
    response_model=list[ProjectResponse],
    responses={status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse}},
)
def api_list_projects(user: ApiUser, session: DbSession) -> list[ProjectResponse]:
    """Только проекты, где текущий пользователь участник."""
    return [ProjectResponse.from_model(project) for project in list_user_projects(session, user.id)]


@api_router.post(
    "",
    summary="Создать проект",
    status_code=status.HTTP_201_CREATED,
    response_model=ProjectResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: {"model": ErrorResponse},
        status.HTTP_409_CONFLICT: {"model": ErrorResponse},
    },
)
def api_create_project(
    payload: ProjectCreate,
    user: ApiUser,
    session: DbSession,
) -> ProjectResponse:
    """Создаёт проект. Создатель сразу становится участником с ролью `owner`."""
    try:
        project = create_project(session, payload, user)
    except ProjectSlugTakenError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=SLUG_TAKEN_MESSAGE,
        ) from None
    return ProjectResponse.from_model(project)


def _render_page(
    request: Request,
    session: Session,
    user: User,
    values: Mapping[str, str],
    error: str | None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    """Одна страница для показа списка, ошибки формы и пустого состояния."""
    return templates.TemplateResponse(
        request,
        "projects.html",
        {
            "projects": list_user_projects(session, user.id),
            "user": user,
            "values": values,
            "error": error,
        },
        status_code=status_code,
    )


def _form_values(name: str, slug: str, repo_url: str, default_branch: str) -> dict[str, str]:
    """Введённые значения возвращаются в форму, чтобы их не набирать заново."""
    return {
        "name": name,
        "slug": slug,
        "repo_url": repo_url,
        "default_branch": default_branch,
    }


@html_router.get("/projects", summary="Список проектов", response_class=HTMLResponse)
def projects_page(request: Request, user: HtmlUser, session: DbSession) -> HTMLResponse:
    """Свои проекты и форма создания проекта."""
    return _render_page(
        request,
        session,
        user,
        _form_values("", "", "", "main"),
        None,
    )


@html_router.post("/projects", summary="Создание проекта из формы", response_class=HTMLResponse)
def projects_create(
    request: Request,
    user: HtmlUser,
    session: DbSession,
    name: Annotated[str, Form()] = "",
    slug: Annotated[str, Form()] = "",
    repo_url: Annotated[str, Form()] = "",
    default_branch: Annotated[str, Form()] = "main",
) -> Response:
    """Успех — 303 на список; ошибка — та же страница с сообщением."""
    values = _form_values(name, slug, repo_url, default_branch)
    try:
        payload = ProjectCreate(
            name=name,
            slug=slug,
            repo_url=repo_url or None,
            default_branch=default_branch,
        )
    except ValidationError:
        return _render_page(
            request,
            session,
            user,
            values,
            FORM_INVALID_MESSAGE,
            status.HTTP_400_BAD_REQUEST,
        )
    try:
        create_project(session, payload, user)
    except ProjectSlugTakenError:
        return _render_page(
            request,
            session,
            user,
            values,
            SLUG_TAKEN_MESSAGE,
            status.HTTP_409_CONFLICT,
        )
    # 303 переводит браузер на GET: обновление страницы не создаёт второй проект.
    return RedirectResponse(url="/projects", status_code=status.HTTP_303_SEE_OTHER)
