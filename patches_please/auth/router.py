"""Вход и выход: REST API и серверный интерфейс (T-004, FR-022, FR-023).

API (`/api/v1/auth/*`) отвечает JSON и описан в `contracts/openapi.yaml`.
Страницы (`/login`, `/logout`) рендерятся Jinja2 и в контракт не входят.
Обе части работают с одним сервисом: различается только формат ответа.
"""

import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.db import get_db

# Шаблоны лежат в корне репозитория, рядом с patches_please/: отсюда это два уровня вверх.
TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

# Зависимость алиасом: аннотации читаются короче, а вызов Depends не попадает
# в значения по умолчанию (ruff B008).
DbSession = Annotated[Session, Depends(get_db)]

# Одно сообщение для неверного пароля и неизвестного email: наличие учётной записи
# не раскрывается, по тексту ответа нельзя отличить один случай от другого.
INVALID_CREDENTIALS_MESSAGE = "Неверный email или пароль"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

api_router = APIRouter(prefix="/api/v1/auth", tags=["аутентификация"])
html_router = APIRouter(include_in_schema=False)


class LoginRequest(BaseModel):
    """Учётные данные для входа в интерфейс."""

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class UserResponse(BaseModel):
    """Пользователь, от имени которого открыта сессия."""

    id: uuid.UUID
    email: str
    role: str


class ErrorResponse(BaseModel):
    """Ошибка запроса в едином формате."""

    detail: str


def _set_session_cookie(response: Response, token: str) -> None:
    """Ставит cookie сессии.

    `secure=False` — ограничение локального стенда: он работает по HTTP, и браузер
    не вернул бы secure-cookie. Для демо-стенда за HTTPS флаг включается в T-024.
    """
    response.set_cookie(
        key=service.SESSION_COOKIE_NAME,
        value=token,
        max_age=int(service.SESSION_LIFETIME.total_seconds()),
        path="/",
        httponly=True,
        samesite="lax",
        secure=False,
    )


def _clear_session_cookie(response: Response) -> None:
    """Удаляет cookie сессии теми же атрибутами, с которыми она ставилась."""
    response.delete_cookie(
        key=service.SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="lax",
        secure=False,
    )


@api_router.post(
    "/login",
    summary="Вход в интерфейс",
    description=(
        "Проверяет email и пароль, создаёт сессию браузера и ставит cookie "
        "`pp_session`.\n\n"
        "Неверный пароль и неизвестный email дают одинаковый ответ 401: "
        "наличие учётной записи не раскрывается."
    ),
    response_model=UserResponse,
    responses={
        status.HTTP_200_OK: {
            "description": "Сессия создана, в Set-Cookie — токен сессии.",
            "headers": {
                "Set-Cookie": {
                    "description": (
                        "Cookie `pp_session`: HttpOnly, SameSite=Lax, Path=/, срок жизни 7 дней."
                    ),
                    "schema": {"type": "string"},
                }
            },
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Неверный email или пароль.",
        },
    },
)
def api_login(
    payload: LoginRequest,
    response: Response,
    session: DbSession,
) -> UserResponse:
    """Проверяет пару email/пароль и открывает сессию в cookie."""
    user = service.authenticate(session, payload.email, payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS_MESSAGE,
        )
    token = service.create_session(session, user)
    _set_session_cookie(response, token)
    return UserResponse(id=user.id, email=user.email, role=user.role)


@api_router.post(
    "/logout",
    summary="Выход из интерфейса",
    description=(
        "Удаляет строку `sessions` по хешу токена из cookie и очищает cookie.\n\n"
        "Без активной сессии отвечает 204: повторный вызов безопасен."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    responses={
        status.HTTP_204_NO_CONTENT: {
            "description": "Сессия закрыта, cookie очищена.",
            "headers": {
                "Set-Cookie": {
                    "description": "Пустое значение `pp_session` с истёкшим сроком.",
                    "schema": {"type": "string"},
                }
            },
        }
    },
)
def api_logout(request: Request, session: DbSession) -> Response:
    """Закрывает сессию и очищает cookie. Без сессии тоже отвечает 204."""
    token = request.cookies.get(service.SESSION_COOKIE_NAME)
    if token:
        service.delete_session(session, token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_session_cookie(response)
    return response


@html_router.get("/login", summary="Страница входа", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    """Форма входа. Ошибок пока нет: страница открыта впервые."""
    return templates.TemplateResponse(
        request,
        "login.html",
        {"error": None, "email": ""},
    )


@html_router.post("/login", summary="Отправка формы входа", response_class=HTMLResponse)
def login_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    session: DbSession,
) -> Response:
    """Успех — 303 на список проектов; ошибка — 401 и та же форма с введённым email."""
    user = service.authenticate(session, email, password)
    if user is None:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": INVALID_CREDENTIALS_MESSAGE, "email": email},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    token = service.create_session(session, user)
    # 303 переводит браузер на GET: повторная отправка формы не создаёт вторую сессию.
    response = RedirectResponse(url="/projects", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookie(response, token)
    return response


@html_router.post("/logout", summary="Выход из интерфейса")
def logout_submit(request: Request, session: DbSession) -> Response:
    """Закрывает сессию и возвращает на страницу входа."""
    token = request.cookies.get(service.SESSION_COOKIE_NAME)
    if token:
        service.delete_session(session, token)
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookie(response)
    return response
