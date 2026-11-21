"""HTTP API Security Gate.

Точка входа процесса `api`: служебные эндпоинты и, начиная с этапа 2,
REST API и веб-интерфейс.
"""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Security Gate",
    description="Автоматизированный контроль безопасности разработки в CI/CD",
    version="0.1.0",
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
