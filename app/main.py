"""HTTP API Security Gate.

Точка входа процесса `api`: служебные эндпоинты и, начиная с этапа 2,
REST API и веб-интерфейс.
"""

from typing import Literal

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.auth.router import api_router as auth_api_router
from app.auth.router import html_router as auth_html_router

app = FastAPI(
    title="Security Gate",
    description="Автоматизированный контроль безопасности разработки в CI/CD",
    version="0.1.0",
)

app.include_router(auth_api_router)
app.include_router(auth_html_router)


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
