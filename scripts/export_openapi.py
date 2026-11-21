"""Экспорт OpenAPI-контракта из приложения (T-007, FR-009).

`contracts/openapi.yaml` — артефакт: источник правды — `app.openapi()`.
Запуск из корня репозитория:

    uv run python -m scripts.export_openapi

Заголовок с пометкой «не править вручную» добавляется здесь: YAML-парсер
комментарии не видит, а человеку понятно происхождение файла.
"""

from pathlib import Path

import yaml

from app.main import app

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "openapi.yaml"

HEADER = """\
# Контракт REST API Security Gate.
# Сгенерирован из app.openapi(); вручную не править.
# Перегенерация: uv run python -m scripts.export_openapi
# Сверка с приложением: uv run pytest tests/test_contract.py
"""


def main() -> None:
    """Собирает схему приложения и перезаписывает файл контракта."""
    schema = app.openapi()
    body = yaml.safe_dump(schema, allow_unicode=True, sort_keys=False, width=1000)
    CONTRACT_PATH.write_text(HEADER + body, encoding="utf-8", newline="\n")
    print(f"Записан {CONTRACT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
