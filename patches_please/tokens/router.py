"""Токены проектов: создание, одноразовый показ, список и отзыв (T-006, FR-024, FR-025).

API описан в `contracts/openapi.yaml`. Страницы управления токенами нет: форма
появится вместе со страницей проекта (T-022) или настроек (T-024), поэтому
HTML-маршрутов здесь не заводим.

Права проверяет `patches_please.auth.permissions` (T-025): создаёт и отзывает
владелец (`owner`), участник (`member`) видит список без открытых значений,
посторонний получает 404 — наличие чужого проекта не раскрывается. Участник
на запись получает 403: проект ему известен, скрывать нечего.
"""

import uuid
from datetime import datetime
from typing import Annotated, Final

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, StringConstraints

from patches_please.auth.dependencies import ApiUser, DbSession
from patches_please.auth.permissions import FORBIDDEN_MESSAGE as FORBIDDEN_MESSAGE
from patches_please.auth.permissions import PROJECT_NOT_FOUND_MESSAGE as PROJECT_NOT_FOUND_MESSAGE
from patches_please.auth.permissions import require_project_member, require_project_owner
from patches_please.auth.router import ErrorResponse
from patches_please.tokens import service
from patches_please.tokens.models import ProjectToken

api_router = APIRouter(prefix="/api/v1/projects", tags=["токены"])

TokenName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]

TOKEN_NOT_FOUND_MESSAGE: Final = "Токен не найден"


class TokenCreate(BaseModel):
    """Название токена: по нему владелец отличает токены в списке."""

    name: TokenName


class TokenResponse(BaseModel):
    """Созданный токен. `token` — открытое значение, единственный раз."""

    id: uuid.UUID
    name: str
    token: str
    created_at: datetime

    @classmethod
    def from_model(cls, stored: ProjectToken, token: str) -> "TokenResponse":
        return cls(
            id=stored.id,
            name=stored.name,
            token=token,
            created_at=stored.created_at,
        )


class TokenListItem(BaseModel):
    """Токен в списке: только метаданные, без открытого значения."""

    id: uuid.UUID
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None

    @classmethod
    def from_model(cls, stored: ProjectToken) -> "TokenListItem":
        return cls(
            id=stored.id,
            name=stored.name,
            created_at=stored.created_at,
            last_used_at=stored.last_used_at,
            revoked_at=stored.revoked_at,
        )


@api_router.get(
    "/{project_id}/tokens",
    summary="Токены проекта",
    description=(
        "Метаданные токенов проекта без открытых значений: открытое значение "
        "показывается только в ответе на создание.\n\n"
        "Порядок — от новых к старым, при равенстве времени — по названию. Список "
        "доступен участнику проекта; посторонний получает 404, чтобы существование "
        "чужого проекта не раскрывалось."
    ),
    response_model=list[TokenListItem],
    responses={
        status.HTTP_200_OK: {
            "description": "Токены проекта; пустой массив — если их нет.",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Нет действующей сессии.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Проект не найден или пользователь не его участник.",
        },
    },
)
def api_list_tokens(
    project_id: uuid.UUID, user: ApiUser, session: DbSession
) -> list[TokenListItem]:
    """Метаданные токенов проекта. Доступно любому участнику, открытых значений нет."""
    require_project_member(session, project_id, user, hide_project=True)
    return [TokenListItem.from_model(stored) for stored in service.list_tokens(session, project_id)]


@api_router.post(
    "/{project_id}/tokens",
    summary="Создать токен проекта",
    description=(
        "Создаёт токен для доступа из CI и возвращает открытое значение ровно "
        "один раз — в ответе 201.\n\n"
        "В базе хранится только SHA-256 токена. Создавать токены может только "
        "владелец проекта (`owner`); участник (`member`) получает 403, "
        "посторонний — 404."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=TokenResponse,
    responses={
        status.HTTP_201_CREATED: {
            "description": (
                "Токен создан. Открытое значение `token` больше не отдаётся ни одним методом."
            ),
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Нет действующей сессии.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "Пользователь участник проекта, но не его владелец.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Проект не найден или пользователь не его участник.",
        },
    },
)
def api_create_token(
    project_id: uuid.UUID,
    payload: TokenCreate,
    user: ApiUser,
    session: DbSession,
) -> TokenResponse:
    """Создаёт токен и показывает открытое значение один раз — в этом ответе."""
    require_project_owner(session, project_id, user)
    token, stored = service.create_token(session, project_id, payload.name)
    return TokenResponse.from_model(stored, token)


@api_router.delete(
    "/{project_id}/tokens/{token_id}",
    summary="Отозвать токен проекта",
    description=(
        "Помечает токен недействительным: заполняет `revoked_at`, строка остаётся "
        "в истории. Отозванный токен не проходит проверку.\n\n"
        "Повторный отзыв тоже отвечает 204. Отзывать токены может только владелец "
        "проекта; токен другого или несуществующего проекта — 404."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_204_NO_CONTENT: {
            "description": "Токен отозван (в том числе повторно).",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Нет действующей сессии.",
        },
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "Пользователь участник проекта, но не его владелец.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Проект или токен этого проекта не найден.",
        },
    },
)
def api_revoke_token(
    project_id: uuid.UUID,
    token_id: uuid.UUID,
    user: ApiUser,
    session: DbSession,
) -> Response:
    """Мягкий отзыв: `revoked_at` заполняется, строка остаётся. Повторный отзыв — 204."""
    require_project_owner(session, project_id, user)
    if not service.revoke_token(session, project_id, token_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=TOKEN_NOT_FOUND_MESSAGE)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
