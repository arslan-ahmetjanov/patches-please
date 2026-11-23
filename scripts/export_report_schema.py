"""Экспорт JSON-схемы отчёта прогона (T-020, FR-008).

`contracts/report.schema.json` — артефакт модели `ScanReport`, а не ручная
копия: поля, типы и обязательность меняются только вместе с моделью. Запуск из
корня репозитория:

    uv run python -m scripts.export_report_schema

Сверка файла с моделью — `tests/test_reports.py`.
"""

from pathlib import Path

from patches_please.reports.json_report import schema_json

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "report.schema.json"


def main() -> None:
    """Собирает схему из модели и перезаписывает файл контракта."""
    SCHEMA_PATH.write_text(schema_json(), encoding="utf-8", newline="\n")
    print(f"Записан {SCHEMA_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
