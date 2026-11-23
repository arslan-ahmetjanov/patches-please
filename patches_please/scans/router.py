"""Прогоны: приём по токену проекта и поллинг статуса (T-008, FR-001, FR-007, FR-019).

CI вызывает `POST /api/v1/scans` с Bearer-токеном проекта и тремя полями:
коммит, ref и провайдер. API пишет строку `scans` со статусом `queued`,
ставит задачу в очередь и отвечает 202 — тем же объектом, который потом отдаёт
`GET /api/v1/scans/{scan_id}`. Логика для GitHub Actions и GitLab CI одна:
провайдер только записывается в историю (FR-019).

Повторный запрос с тем же проектом и коммитом возвращает существующий прогон:
второй строки и второй задачи не появляется (план, «Лимиты»). Гонка двух
одновременных запросов уникальным индексом не закрыта: лимит «один активный
прогон на проект» — изменение схемы БД и отдельная задача после T-009.

Обе операции требуют токен проекта. Cookie-сессия для чтения прогона появится
вместе со страницами (T-022, T-025) — контракт не обещает её раньше.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, StringConstraints
from rq import Queue
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.auth.dependencies import DbSession
from patches_please.auth.router import ErrorResponse
from patches_please.policy.verdict import Verdict
from patches_please.scans import queue as scan_queue
from patches_please.scans.models import Scan
from patches_please.scans.queue import get_scan_queue
from patches_please.scans.service import ScanStatus
from patches_please.tokens.models import ProjectToken
from patches_please.tokens.service import verify_token

api_router = APIRouter(prefix="/api/v1/scans", tags=["прогоны"])

# Полный SHA-1 или SHA-256 в нижнем регистре: сокращённый хеш неоднозначен и
# сделал бы дедупликацию по коммиту неверной.
CommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
# Git ref без пробелов: `main`, `refs/heads/main`, `refs/pull/1/head`.
RefName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255, pattern=r"^\S+$")
]

TOKEN_REQUIRED_MESSAGE: Final = "Требуется действующий токен проекта"
SCAN_NOT_FOUND_MESSAGE: Final = "Прогон не найден"

ScanQueue = Annotated[Queue, Depends(get_scan_queue)]


class Provider(StrEnum):
    """CI-провайдер, из которого пришёл запуск. На проверку не влияет (FR-019)."""

    GITHUB = "github"
    GITLAB = "gitlab"


class ScanCreate(BaseModel):
    """Запуск прогона: что именно проверять. Провайдер — только для истории."""

    commit_sha: CommitSha
    ref: RefName
    provider: Provider


class ScanResponse(BaseModel):
    """Прогон в ответе API: одинаковый набор полей у POST и GET."""

    id: uuid.UUID
    status: ScanStatus
    commit_sha: str
    ref: str
    provider: Provider
    created_at: datetime
    verdict: Verdict | None

    @classmethod
    def from_model(cls, scan: Scan) -> "ScanResponse":
        return cls(
            id=scan.id,
            status=ScanStatus(scan.status),
            commit_sha=scan.commit_sha,
            ref=scan.ref,
            provider=Provider(scan.provider),
            created_at=scan.created_at,
            verdict=Verdict(scan.verdict) if scan.verdict is not None else None,
        )


def _unauthorized() -> HTTPException:
    """Одна реакция на отсутствующий, неизвестный и отозванный токен."""
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=TOKEN_REQUIRED_MESSAGE,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_project_token(
    session: DbSession,
    authorization: Annotated[str | None, Header()] = None,
) -> ProjectToken:
    """Токен проекта из заголовка `Authorization: Bearer pp_...`.

    Схема разбирается вручную, как и cookie-сессия: так все схемы безопасности
    объявлены в одном месте (`patches_please/api.py`), а не появляются из FastAPI молча.
    Успешная проверка обновляет `last_used_at` — это делает `verify_token`.
    """
    if authorization is None:
        raise _unauthorized()
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise _unauthorized()
    stored = verify_token(session, value.strip())
    if stored is None:
        raise _unauthorized()
    return stored


ProjectTokenAuth = Annotated[ProjectToken, Depends(get_project_token)]


def find_scan(session: Session, project_id: uuid.UUID, commit_sha: str) -> Scan | None:
    """Прогон этого коммита в проекте; при нескольких строках — самая свежая."""
    statement = (
        select(Scan)
        .where(Scan.project_id == project_id, Scan.commit_sha == commit_sha)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return session.scalar(statement)


def start_scan(session: Session, project_id: uuid.UUID, payload: ScanCreate) -> tuple[Scan, bool]:
    """Возвращает прогон коммита и признак «создан сейчас».

    Признак нужен, чтобы не ставить вторую задачу на тот же коммит: повторный
    запрос отдаёт существующий прогон, а очередь не получает дубль.
    """
    existing = find_scan(session, project_id, payload.commit_sha)
    if existing is not None:
        return existing, False
    scan = Scan(
        project_id=project_id,
        commit_sha=payload.commit_sha,
        ref=payload.ref,
        provider=str(payload.provider),
    )
    session.add(scan)
    session.commit()
    # id, created_at и статус по умолчанию выставляет PostgreSQL: читаем строку обратно.
    session.refresh(scan)
    return scan, True


@api_router.post(
    "",
    summary="Запустить прогон",
    description=(
        "Создаёт прогон со статусом `queued` и ставит задачу в очередь; "
        "отвечает 202.\n\n"
        "Доступ — токен проекта в заголовке `Authorization: Bearer pp_...`. "
        "Повторный запрос с тем же проектом и коммитом возвращает существующий "
        "прогон: второй строки и второй задачи не появляется. Провайдер "
        "(`github` или `gitlab`) записывается в историю, но на набор проверок "
        "и вердикт не влияет."
    ),
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanResponse,
    responses={
        status.HTTP_202_ACCEPTED: {
            "description": "Прогон принят: строка создана или найдена, задача поставлена.",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Токен отсутствует, неизвестен или отозван.",
        },
    },
)
def api_start_scan(
    payload: ScanCreate,
    token: ProjectTokenAuth,
    session: DbSession,
    queue: ScanQueue,
) -> ScanResponse:
    """Создаёт прогон этого коммита, если его ещё нет, и ставит задачу в очередь."""
    scan, created = start_scan(session, token.project_id, payload)
    if created:
        scan_queue.enqueue_scan(queue, scan.id)
    return ScanResponse.from_model(scan)


@api_router.get(
    "/{scan_id}",
    summary="Статус прогона",
    description=(
        "Возвращает статус прогона, коммит, ветку, провайдера, время создания и "
        "вердикт. CI поллит этот метод и завершает job по вердикту.\n\n"
        "Доступ — токен проекта, которым запускался прогон. Прогон другого "
        "проекта и несуществующий идентификатор выглядят одинаково — 404."
    ),
    response_model=ScanResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Прогон этого проекта.",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Токен отсутствует, неизвестен или отозван.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Прогон не найден или принадлежит другому проекту.",
        },
    },
)
def api_get_scan(
    scan_id: uuid.UUID,
    token: ProjectTokenAuth,
    session: DbSession,
) -> ScanResponse:
    """Статус прогона. Чужой прогон не отличим от несуществующего."""
    scan = session.scalar(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == token.project_id)
    )
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=SCAN_NOT_FOUND_MESSAGE,
        )
    return ScanResponse.from_model(scan)
