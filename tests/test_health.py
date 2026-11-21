"""Служебный эндпоинт /health (T-001, CON-002)."""

import asyncio

import httpx

from app.main import app


async def _get_health() -> httpx.Response:
    """Запрос к приложению через ASGI-транспорт, без сетевого порта."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://security-gate") as client:
        return await client.get("/health")


def test_con_002_health_returns_200() -> None:
    """Healthcheck стека Docker Compose должен получать 200 без БД и сети."""
    response = asyncio.run(_get_health())

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
