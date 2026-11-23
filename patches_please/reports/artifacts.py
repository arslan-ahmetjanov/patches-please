"""Запись отчётов прогона как артефактов (T-020, FR-008).

Два файла на прогон — `<scan_id>.json` и `<scan_id>.html` — в каталоге из
`REPORTS_DIR`, по умолчанию `reports/` от рабочего каталога. Каталог в
`.gitignore`, поэтому локальный прогон не мусорит в репозитории; в контейнере
worker это смонтированный том (`docker-compose.yml`), и каталог принадлежит
пользователю процесса.

Сбой записи не отменяет прогон: файлы — следствие уже сохранённых находок,
метрик и вердикта, их можно пересобрать повторной обработкой. Решение, что
делать с ошибкой, принимает конвейер (`patches_please.scans.pipeline`): он
пишет предупреждение в лог и оставляет прогон `done`.
"""

import os
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from patches_please.metrics.service import RunMetrics
from patches_please.normalize.model import Severity
from patches_please.projects.models import Project
from patches_please.reports.html_report import write_html
from patches_please.reports.json_report import ScanReport, build_report, write_json
from patches_please.scanners.base import ScannerRun
from patches_please.scans.models import FindingRecord, Scan

# Переменная окружения задаёт каталог отчётов; в образе worker — /app/reports.
REPORTS_DIR_ENV: Final = "REPORTS_DIR"
DEFAULT_REPORTS_DIR: Final = Path("reports")
JSON_SUFFIX: Final = ".json"
HTML_SUFFIX: Final = ".html"


@dataclass(frozen=True, slots=True)
class ReportArtifacts:
    """Пути двух файлов отчёта одного прогона."""

    json_path: Path
    html_path: Path


def reports_directory() -> Path:
    """Каталог отчётов из `REPORTS_DIR` или `reports/` от рабочего каталога."""
    configured = os.environ.get(REPORTS_DIR_ENV, "").strip()
    return Path(configured) if configured else DEFAULT_REPORTS_DIR


def artifact_paths(directory: Path, scan_id: uuid.UUID) -> ReportArtifacts:
    """Имена файлов отчёта: идентификатор прогона уникален, подкаталоги не нужны."""
    return ReportArtifacts(
        json_path=directory / f"{scan_id}{JSON_SUFFIX}",
        html_path=directory / f"{scan_id}{HTML_SUFFIX}",
    )


def save_reports(
    scan: Scan,
    project: Project,
    records: Sequence[FindingRecord],
    metrics: RunMetrics,
    runs: Iterable[ScannerRun],
    block_severities: Iterable[Severity],
    directory: Path | None = None,
) -> ReportArtifacts:
    """Строит отчёт и пишет оба файла; возвращает пути записанного.

    `directory` — точка подмены для тестов; боевой вызов берёт каталог из
    окружения. Ошибка ввода-вывода пробрасывается `OSError`: решение о судьбе
    прогона принимает конвейер.
    """
    report: ScanReport = build_report(scan, project, records, metrics, runs, block_severities)
    target = directory if directory is not None else reports_directory()
    target.mkdir(parents=True, exist_ok=True)
    paths = artifact_paths(target, scan.id)
    write_json(report, paths.json_path)
    write_html(report, paths.html_path)
    return paths
