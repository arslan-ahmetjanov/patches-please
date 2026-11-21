"""Сверка контракта с живой схемой приложения (T-007, FR-009).

`contracts/openapi.yaml` — артефакт `app.openapi()`, а не ручная копия. Тест
ловит два класса ошибок: файл разошёлся с приложением после правки роутера и
схема перестала быть валидной (повторяющиеся `operationId`, висячие `$ref`,
операция без ответов, незадекларированный path-параметр).

Новых зависимостей нет: YAML читается PyYAML, который уже приходит транзитивно
с `uvicorn[standard]`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from conftest import AppClient

from app.auth.service import SESSION_COOKIE_NAME
from app.main import app

CONTRACT_PATH = Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml"
HTTP_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
PATH_PARAMETER = re.compile(r"{([^}]+)}")

# Операции, которым нужна cookie-сессия. Вход, выход и health работают без неё.
COOKIE_PROTECTED = {
    ("get", "/api/v1/projects"),
    ("post", "/api/v1/projects"),
    ("get", "/api/v1/projects/{project_id}/tokens"),
    ("post", "/api/v1/projects/{project_id}/tokens"),
    ("delete", "/api/v1/projects/{project_id}/tokens/{token_id}"),
}
PUBLIC_OPERATIONS = {
    ("get", "/health"),
    ("post", "/api/v1/auth/login"),
    ("post", "/api/v1/auth/logout"),
}


@pytest.fixture(scope="module")
def contract() -> dict[str, Any]:
    """Разобранный файл контракта."""
    loaded = yaml.safe_load(CONTRACT_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


@pytest.fixture(scope="module")
def live_schema() -> dict[str, Any]:
    """Схема, которую приложение отдаёт на `/openapi.json`."""
    return app.openapi()


def _operations(schema: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Все операции схемы: путь, метод в нижнем регистре, объект операции."""
    result: list[tuple[str, str, dict[str, Any]]] = []
    for path, item in schema["paths"].items():
        for method, operation in item.items():
            if method in HTTP_METHODS:
                result.append((path, method, operation))
    return result


def _first_difference(left: Any, right: Any, path: str = "$") -> str | None:
    """Первое расхождение двух JSON-подобных структур — чтобы тест не тонул в диффе."""
    if type(left) is not type(right):
        return f"{path}: тип {type(left).__name__} != {type(right).__name__}"
    if isinstance(left, dict):
        left_keys, right_keys = set(left), set(right)
        if left_keys != right_keys:
            extra = sorted(left_keys ^ right_keys)
            return f"{path}: лишние или недостающие ключи {extra}"
        for key, value in left.items():
            difference = _first_difference(value, right[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return f"{path}: длина {len(left)} != {len(right)}"
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            difference = _first_difference(left_item, right_item, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if left != right:
        return f"{path}: {left!r} != {right!r}"
    return None


def _collect_refs(node: Any) -> set[str]:
    """Все `$ref` в схеме, включая вложенные."""
    refs: set[str] = set()
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            refs.add(ref)
        for value in node.values():
            refs |= _collect_refs(value)
    elif isinstance(node, list):
        for value in node:
            refs |= _collect_refs(value)
    return refs


def _resolve_ref(schema: dict[str, Any], ref: str) -> Any:
    """Разрешает локальную ссылку `#/...`; `None`, если цели нет."""
    if not ref.startswith("#/"):
        return None
    node: Any = schema
    for part in ref[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _operation(schema: dict[str, Any], method: str, path: str) -> dict[str, Any]:
    operation = schema["paths"][path][method]
    assert isinstance(operation, dict)
    return operation


def test_fr_009_contract_matches_live_schema(
    contract: dict[str, Any], live_schema: dict[str, Any]
) -> None:
    """Файл побайтово эквивалентен живой схеме по путям, ответам и компонентам."""
    difference = _first_difference(contract, live_schema)
    assert difference is None, f"Контракт разошёлся с приложением: {difference}"


def test_fr_009_schema_is_structurally_valid(contract: dict[str, Any]) -> None:
    """Минимальная валидация OpenAPI без внешнего валидатора."""
    assert contract["openapi"].startswith("3.1.")
    assert contract["info"]["title"]
    assert contract["info"]["version"]
    assert contract["paths"]

    for ref in _collect_refs(contract):
        assert _resolve_ref(contract, ref) is not None, f"Висячий $ref: {ref}"

    seen_operation_ids: set[str] = set()
    for path, method, operation in _operations(contract):
        operation_id = operation.get("operationId")
        assert operation_id, f"{method.upper()} {path}: нет operationId"
        assert operation_id not in seen_operation_ids, f"Повторный operationId: {operation_id}"
        seen_operation_ids.add(operation_id)

        responses = operation.get("responses")
        assert responses, f"{method.upper()} {path}: нет responses"
        for status_code, response in responses.items():
            assert response.get("description"), (
                f"{method.upper()} {path} {status_code}: нет description"
            )

        declared = {
            parameter["name"]
            for parameter in operation.get("parameters", [])
            if parameter.get("in") == "path"
        }
        assert set(PATH_PARAMETER.findall(path)) == declared, (
            f"{method.upper()} {path}: path-параметры не совпадают с объявленными"
        )

    for name, component in contract["components"]["schemas"].items():
        assert component.get("title") == name, f"Схема {name}: title не совпадает с именем"


def test_fr_009_security_schemes_describe_real_behaviour(contract: dict[str, Any]) -> None:
    """Cookie-схема стоит там, где сессия действительно требуется; Bearer пока объявлен."""
    schemes = contract["components"]["securitySchemes"]
    cookie = schemes["cookieAuth"]
    assert cookie["type"] == "apiKey"
    assert cookie["in"] == "cookie"
    assert cookie["name"] == SESSION_COOKIE_NAME

    bearer = schemes["bearerAuth"]
    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"

    secured = {
        (method, path)
        for path, method, operation in _operations(contract)
        if "security" in operation
    }
    assert secured == COOKIE_PROTECTED
    for method, path in COOKIE_PROTECTED:
        assert _operation(contract, method, path)["security"] == [{"cookieAuth": []}]

    for method, path in PUBLIC_OPERATIONS:
        assert "security" not in _operation(contract, method, path)

    # Проверки Bearer в запросах ещё нет (T-008): ни одна операция его не требует.
    for _, _, operation in _operations(contract):
        for requirement in operation.get("security", []):
            assert "bearerAuth" not in requirement


def test_fr_009_validation_error_schema_matches_handler(client: AppClient) -> None:
    """Схема 422 и фактический ответ обработчика перечисляют одни и те же поля."""
    schema = app.openapi()["components"]["schemas"]["ValidationError"]
    assert set(schema["properties"]) == {"type", "loc", "msg"}
    assert set(schema["required"]) == {"type", "loc", "msg"}

    response = client.post("/api/v1/auth/login", json={"email": "", "password": ""})
    assert response.status_code == 422
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}


def test_fr_009_openapi_endpoint_serves_contract(client: AppClient) -> None:
    """Публичный `/openapi.json` отдаёт ту же схему, что лежит в контракте."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json() == app.openapi()
