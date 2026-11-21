"""Служебный эндпоинт /health (T-001, CON-002)."""

from conftest import AppClient


def test_con_002_health_returns_200(client: AppClient) -> None:
    """Healthcheck стека Docker Compose должен получать 200 без БД и сети."""
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
