"""Текущий пользователь из cookie-сессии (T-005, FR-017).

Проверка одна на два входа: API отвечает 401, страница уводит на `/login`.
Сервис сессий (`patches_please.auth.service`) отдаёт владельца токена, здесь только
различается реакция на его отсутствие.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.auth.models import User
from patches_please.db import get_db

DbSession = Annotated[Session, Depends(get_db)]

# Одно сообщение для всех закрытых методов API: какая именно сессия нужна —
# не раскрывается, отсутствие cookie и протухший токен выглядят одинаково.
LOGIN_REQUIRED_MESSAGE = "Требуется вход"


class LoginRequiredError(Exception):
    """Действующей сессии нет: HTML-маршрут перенаправляет на `/login`."""


def get_current_user_optional(request: Request, session: DbSession) -> User | None:
    """Владелец действующей сессии или `None`, если cookie нет.

    Без cookie база не читается: анонимный запрос не открывает соединение.
    """
    token = request.cookies.get(service.SESSION_COOKIE_NAME)
    if not token:
        return None
    return service.get_session_user(session, token)


def get_api_user(user: Annotated[User | None, Depends(get_current_user_optional)]) -> User:
    """Пользователь для REST API: без сессии — 401."""
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=LOGIN_REQUIRED_MESSAGE,
        )
    return user


def get_html_user(user: Annotated[User | None, Depends(get_current_user_optional)]) -> User:
    """Пользователь для страниц: без сессии — сигнал на редирект `/login`."""
    if user is None:
        raise LoginRequiredError
    return user


ApiUser = Annotated[User, Depends(get_api_user)]
HtmlUser = Annotated[User, Depends(get_html_user)]
