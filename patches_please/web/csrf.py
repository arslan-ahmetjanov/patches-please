"""CSRF-защита серверных форм: double-submit cookie (T-024).

Токен живёт в cookie `pp_csrf` и в скрытом поле формы. `POST` сравнивает оба
значения через `secrets.compare_digest`: чужой сайт cookie прочитать не может,
поэтому запрос без совпадающего токена отклоняется с кодом 403.

Библиотека не нужна: формы серверные, JavaScript в них не участвует, а cookie
закрыта от чтения (`HttpOnly`) и выдаётся тем же ответом, что и страница.
Токен не хранится в базе: подделанная cookie без совпадения с полем ничего
не даёт. Срок жизни равен сроку сессии — форма, открытая вчера, ещё отправится.
"""

import secrets
from typing import Final

from fastapi import HTTPException, Request, Response, status

from patches_please.auth.cookies import cookies_secure
from patches_please.auth.service import SESSION_LIFETIME

CSRF_COOKIE_NAME: Final = "pp_csrf"
CSRF_FIELD_NAME: Final = "csrf_token"
# Совпадает с `SESSION_LIFETIME`: отдельный срок форме не нужен.
CSRF_MAX_AGE: Final = int(SESSION_LIFETIME.total_seconds())
CSRF_INVALID_MESSAGE: Final = (
    "CSRF-токен отсутствует или не совпадает. Обновите страницу и повторите."
)


def issue_token() -> str:
    """Новый случайный токен: 32 байта энтропии в URL-безопасном виде."""
    return secrets.token_urlsafe(32)


def token_from_request(request: Request) -> str:
    """Токен из cookie или новый, если cookie ещё нет."""
    return request.cookies.get(CSRF_COOKIE_NAME) or issue_token()


def set_csrf_cookie(response: Response, token: str) -> None:
    """Ставит cookie CSRF-токена теми же атрибутами, что и cookie сессии."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=CSRF_MAX_AGE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=cookies_secure(),
    )


def require_csrf(request: Request, submitted: str | None) -> None:
    """Сверяет токен формы с cookie; расхождение или пустое поле — 403.

    Сравниваются байты, а не строки: `compare_digest` для `str` принимает только
    ASCII, а присланное поле может содержать любые символы.
    """
    cookie = request.cookies.get(CSRF_COOKIE_NAME) or ""
    token = (submitted or "").strip()
    if not cookie or not token or not secrets.compare_digest(cookie.encode(), token.encode()):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=CSRF_INVALID_MESSAGE,
        )
