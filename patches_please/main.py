"""HTTP API Patches, Please.

Точка входа процесса `api`: служебные эндпоинты, REST API и веб-интерфейс.
"""

from functools import partial
from typing import Literal

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from patches_please.api import build_openapi_schema
from patches_please.auth.dependencies import LoginRequiredError
from patches_please.auth.router import api_router as auth_api_router
from patches_please.auth.router import html_router as auth_html_router
from patches_please.policy.router import api_router as policy_api_router
from patches_please.projects.router import api_router as projects_api_router
from patches_please.projects.router import html_router as projects_html_router
from patches_please.scans.router import api_router as scans_api_router
from patches_please.tokens.router import api_router as tokens_api_router
from patches_please.web.router import html_router as web_html_router

app = FastAPI(
    title="Patches, Please",
    description="Автоматизированный контроль безопасности разработки в CI/CD",
    version="0.1.0",
)

# Схема собирается в patches_please/api.py: там же схемы безопасности и точная форма
# ValidationError, которую не вывести из обработчика 422 автоматически.
app.openapi = partial(build_openapi_schema, app)  # type: ignore[method-assign]

app.include_router(auth_api_router)
app.include_router(auth_html_router)
app.include_router(policy_api_router)
app.include_router(projects_api_router)
app.include_router(projects_html_router)
app.include_router(tokens_api_router)
app.include_router(scans_api_router)
app.include_router(web_html_router)


@app.exception_handler(LoginRequiredError)
async def login_required_handler(request: Request, exc: LoginRequiredError) -> RedirectResponse:
    """Страница без сессии уводит на `/login`.

    303 — чтобы браузер запросил страницу входа методом GET, а не повторил POST.
    """
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """422 в формате контракта: только `type`, `loc`, `msg` у каждой ошибки.

    Стандартный обработчик FastAPI кладёт в ответ ещё `input` и `ctx`, то есть
    дословно повторяет присланное значение — в том числе пароль из формы входа.
    Эти поля отбрасываются, как и описано схемой `ValidationError` в контракте.
    """
    errors = [
        {"type": error["type"], "loc": list(error["loc"]), "msg": error["msg"]}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": errors}
    )


class HealthResponse(BaseModel):
    """Ответ healthcheck-а: сервис принимает запросы."""

    status: Literal["ok"] = "ok"


@app.get("/health", tags=["служебные"], summary="Проверка живости сервиса")
def health() -> HealthResponse:
    """Отвечает 200, пока процесс принимает запросы.

    Используется healthcheck-ом Docker Compose и внешним мониторингом.
    """
    return HealthResponse()
