"""Сборка OpenAPI-схемы для контракта REST API (T-007, FR-009).

Живая схема FastAPI — источник правды: `contracts/openapi.yaml` генерируется
из неё скриптом `scripts/export_openapi.py` и сверяется тестом
`tests/test_contract.py`.

FastAPI выводит из кода пути, модели и коды ответов, но не знает двух вещей:
какие схемы безопасности действуют и что обработчик 422 из `patches_please.main` отдаёт
меньше полей, чем стандартная схема `ValidationError`. Эти два расхождения
закрываются здесь, а не правкой сгенерированного файла.
"""

from typing import Any, Final

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

from patches_please.auth.service import SESSION_COOKIE_NAME

COOKIE_SCHEME: Final = "cookieAuth"
BEARER_SCHEME: Final = "bearerAuth"

# Операции, которым действительно нужна cookie-сессия. Вход, выход и health
# работают без неё, поэтому требования безопасности им не ставим.
COOKIE_PROTECTED_OPERATIONS: Final = (
    ("get", "/api/v1/projects"),
    ("post", "/api/v1/projects"),
    ("get", "/api/v1/projects/{project_id}/tokens"),
    ("post", "/api/v1/projects/{project_id}/tokens"),
    ("delete", "/api/v1/projects/{project_id}/tokens/{token_id}"),
)

# Операции прогонов: CI приходит с токеном проекта, сессии у него нет (T-008).
BEARER_PROTECTED_OPERATIONS: Final = (
    ("post", "/api/v1/scans"),
    ("get", "/api/v1/scans/{scan_id}"),
)

SECURITY_SCHEMES: Final[dict[str, dict[str, Any]]] = {
    COOKIE_SCHEME: {
        "type": "apiKey",
        "in": "cookie",
        "name": SESSION_COOKIE_NAME,
        "description": (
            "Cookie-сессия интерфейса: ставится `POST /api/v1/auth/login`, живёт "
            "7 дней, HttpOnly, SameSite=Lax, Path=/."
        ),
    },
    BEARER_SCHEME: {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "pp_<token>",
        "description": (
            "Токен проекта для CI: `Authorization: Bearer pp_...`, выдаётся "
            "`POST /api/v1/projects/{project_id}/tokens`. Требуется методами "
            "прогонов: запуск и поллинг статуса."
        ),
    },
}


def _drop_unused_validation_fields(schema: dict[str, Any]) -> None:
    """Убирает `input` и `ctx` из `ValidationError`.

    Обработчик 422 в `patches_please.main` отдаёт только `type`, `loc` и `msg`, а
    стандартная схема FastAPI перечисляет ещё `input` и `ctx`. Без этой правки
    контракт обещал бы поля, которых в ответе нет.
    """
    components = schema.get("components")
    if not isinstance(components, dict):
        return
    schemas = components.get("schemas")
    if not isinstance(schemas, dict):
        return
    validation_error = schemas.get("ValidationError")
    if not isinstance(validation_error, dict):
        return
    properties = validation_error.get("properties")
    if isinstance(properties, dict):
        properties.pop("input", None)
        properties.pop("ctx", None)


def _add_security(schema: dict[str, Any]) -> None:
    """Объявляет схемы безопасности и вешает их на защищённые операции."""
    components = schema.setdefault("components", {})
    components["securitySchemes"] = SECURITY_SCHEMES
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        return
    protected = (
        (COOKIE_SCHEME, COOKIE_PROTECTED_OPERATIONS),
        (BEARER_SCHEME, BEARER_PROTECTED_OPERATIONS),
    )
    for scheme, operations in protected:
        for method, path in operations:
            operation = paths.get(path, {}).get(method)
            if isinstance(operation, dict):
                operation["security"] = [{scheme: []}]


def build_openapi_schema(app: FastAPI) -> dict[str, Any]:
    """Собирает схему один раз и кеширует её в приложении, как это делает FastAPI."""
    if app.openapi_schema is not None:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    _drop_unused_validation_fields(schema)
    _add_security(schema)
    app.openapi_schema = schema
    return schema
