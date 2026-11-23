"""Политика проекта: пороги вердикта по severity (T-017, FR-004, FR-014).

`PUT /api/v1/projects/{project_id}/policy` создаёт или заменяет политику
целиком: набор блокирующих уровней, режим деградации и таймаут сканеров.
Ответ — действующая политика проекта. Отдельного чтения в API нет: страница
настроек читает политику через `load_policy` (T-024) и в контракт не входит.

Права до T-025 проверяются локально: управляет политикой только владелец
проекта (`owner`). Участник получает 403, посторонний — 404, чтобы наличие
чужого проекта не раскрывалось.
"""

import uuid

from fastapi import APIRouter, status
from pydantic import BaseModel, Field

from patches_please.auth.dependencies import ApiUser, DbSession
from patches_please.auth.router import ErrorResponse
from patches_please.normalize.model import Severity
from patches_please.policy.models import Policy
from patches_please.policy.verdict import (
    DEFAULT_SCANNER_TIMEOUT_SEC,
    FailMode,
    upsert_policy,
)
from patches_please.tokens.router import require_project_owner

api_router = APIRouter(prefix="/api/v1/projects", tags=["политика"])


class PolicyUpdate(BaseModel):
    """Полная замена политики: `PUT` перезаписывает все поля строки.

    Пустой `block_severities` допустим: политика, которая ничего не блокирует.
    Неизвестный уровень отсекается схемой и даёт 422.
    """

    block_severities: list[Severity]
    fail_mode: FailMode = FailMode.OPEN
    scanner_timeout_sec: int = Field(default=DEFAULT_SCANNER_TIMEOUT_SEC, ge=1)


class PolicyResponse(BaseModel):
    """Действующая политика проекта: то, что записано в `policies`."""

    project_id: uuid.UUID
    block_severities: list[Severity]
    fail_mode: FailMode
    scanner_timeout_sec: int

    @classmethod
    def from_model(cls, policy: Policy) -> "PolicyResponse":
        return cls(
            project_id=policy.project_id,
            block_severities=[Severity(value) for value in policy.block_severities],
            fail_mode=FailMode(policy.fail_mode),
            scanner_timeout_sec=policy.scanner_timeout_sec,
        )


@api_router.put(
    "/{project_id}/policy",
    summary="Задать политику проекта",
    description=(
        "Создаёт или заменяет политику проекта целиком: набор блокирующих "
        "уровней severity, режим деградации и таймаут сканеров.\n\n"
        "Вердикт `fail` получает прогон, где есть новая неисключённая находка "
        "блокирующего уровня; иначе `pass`. Пока политика не задана, блокируются "
        "`critical` и `high`.\n\n"
        "Доступ — только владелец проекта (`owner`). Участник получает 403, "
        "посторонний — 404. Неизвестный уровень severity — 422."
    ),
    response_model=PolicyResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Политика сохранена; ответ содержит действующие значения.",
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
def api_put_policy(
    project_id: uuid.UUID,
    payload: PolicyUpdate,
    user: ApiUser,
    session: DbSession,
) -> PolicyResponse:
    """Полная замена политики проекта; правит только владелец."""
    require_project_owner(session, project_id, user)
    policy = upsert_policy(
        session,
        project_id,
        block_severities=payload.block_severities,
        fail_mode=payload.fail_mode,
        scanner_timeout_sec=payload.scanner_timeout_sec,
    )
    return PolicyResponse.from_model(policy)
