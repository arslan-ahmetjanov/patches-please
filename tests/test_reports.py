"""Отчёты прогона в JSON и HTML (T-020, FR-008, FR-015).

Быстрые тесты строят объекты в памяти и проверяют модель отчёта, схему,
шаблон и запись файлов; интеграционные проводят прогон через конвейер и
смотрят, что рядом с вердиктом появились два файла.

Проверка «JSON валиден по схеме» идёт без новой зависимости: файл
`contracts/report.schema.json` сравнивается со схемой модели `ScanReport`, а
записанный JSON разбирается той же моделью — расхождение полей или типов
всплывает как ошибка валидации.
"""

import hashlib
import json
import logging
import uuid
from collections.abc import Sequence
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from patches_please.metrics.service import RunMetrics
from patches_please.normalize.model import FindingType, Severity
from patches_please.policy.classify import FindingState
from patches_please.policy.verdict import Verdict
from patches_please.projects.models import Project
from patches_please.reports.artifacts import save_reports
from patches_please.reports.html_report import render_html
from patches_please.reports.json_report import (
    ScanReport,
    build_report,
    render_json,
    schema_document,
)
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.pipeline import execute_scan
from patches_please.scans.service import ScanStatus, mark_running

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "report.schema.json"
PIPELINE_LOGGER = "patches_please.scans.pipeline"

SHA = "d" * 40
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
DURATION_SEC = 42.0
SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def _project() -> Project:
    """Проект без базы: отчёту нужны имя, slug и идентификатор."""
    return Project(id=uuid.uuid4(), name="Демо", slug="demo")


def _scan(project: Project, *, verdict: Verdict = Verdict.PASS) -> Scan:
    """Завершённый прогон с вердиктом: остальные поля — для шапки отчёта."""
    return Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        commit_sha=SHA,
        ref="refs/heads/main",
        provider="github",
        status=str(ScanStatus.DONE),
        verdict=str(verdict),
        created_at=START,
        started_at=START,
        finished_at=START + timedelta(seconds=DURATION_SEC),
    )


def _record(
    scan: Scan,
    index: int,
    *,
    severity: Severity = Severity.HIGH,
    state: FindingState = FindingState.NEW,
    excluded: bool = False,
) -> FindingRecord:
    """Находка с уникальным fingerprint: правило, путь и строка зависят от индекса."""
    rule_id = f"rule-{index}"
    path = f"src/module_{index}.py"
    line = index + 10
    return FindingRecord(
        id=uuid.uuid4(),
        scan_id=scan.id,
        fingerprint=hashlib.sha256(f"{rule_id}:{path}:{line}".encode()).hexdigest(),
        scanner="semgrep",
        rule_id=rule_id,
        finding_type=str(FindingType.SAST),
        severity=str(severity),
        path=path,
        line=line,
        message=f"Находка {rule_id}",
        state=str(state),
        excluded=excluded,
    )


def _metrics(records: Sequence[FindingRecord], *, fixed: int = 0) -> RunMetrics:
    """Метрики FR-015 по тому же набору находок: набор уровней полный."""
    counts = dict.fromkeys(SEVERITY_KEYS, 0)
    for record in records:
        counts[record.severity] += 1
    excluded = sum(1 for record in records if record.excluded)
    return RunMetrics(
        duration_sec=DURATION_SEC,
        findings_by_severity=counts,
        new=sum(1 for record in records if record.state == FindingState.NEW),
        fixed=fixed,
        excluded_ratio=excluded / len(records) if records else 0.0,
    )


def _run(
    scanner: str = "semgrep",
    *,
    status: ScannerStatus = ScannerStatus.OK,
    error: str | None = None,
) -> ScannerRun:
    """Итог запуска сканера: у неуспешного есть причина, у успешного — SARIF."""
    return ScannerRun(
        scanner=scanner,
        status=status,
        duration_ms=120,
        sarif_path=Path(f"{scanner}.sarif") if status is ScannerStatus.OK else None,
        error=error,
        tool_version="1.0",
    )


def _report(
    *,
    project: Project | None = None,
    records: Sequence[FindingRecord] | None = None,
    runs: Sequence[ScannerRun] | None = None,
    fixed: int = 0,
    verdict: Verdict = Verdict.PASS,
) -> ScanReport:
    """Отчёт по завершённому прогону; по умолчанию — одна новая `high`."""
    project = project or _project()
    scan = _scan(project, verdict=verdict)
    records = list(records) if records is not None else [_record(scan, 1)]
    runs = list(runs) if runs is not None else [_run()]
    return build_report(
        scan, project, records, _metrics(records, fixed=fixed), runs, [Severity.CRITICAL]
    )


# --- FR-008: JSON по схеме -------------------------------------------------------


def test_fr_008_json_report_matches_schema() -> None:
    """Схема в контракте — та же, что у модели, а JSON разбирается моделью."""
    assert SCHEMA_PATH.is_file()
    assert json.loads(SCHEMA_PATH.read_text(encoding="utf-8")) == schema_document()

    report = _report()
    payload = json.loads(render_json(report))
    assert ScanReport.model_validate(payload) == report
    assert payload["schema_version"] == "1"
    assert payload["scan"]["commit_sha"] == SHA
    assert payload["scan"]["project"]["slug"] == "demo"


def test_fr_008_empty_run_builds_report() -> None:
    """Пустой прогон — законный отчёт: нули остаются нулями, шаблон не падает."""
    report = _report(records=[], runs=[])

    assert report.totals.findings == 0
    assert report.totals.degraded_checks == 0
    assert report.metrics.findings_by_severity == dict.fromkeys(SEVERITY_KEYS, 0)
    assert report.metrics.new == 0

    html = render_html(report)
    assert "Находок нет." in html
    assert "Запусков сканеров нет." in html


# --- FR-008: HTML -----------------------------------------------------------------


def test_fr_008_html_contains_every_finding() -> None:
    """В HTML есть каждая находка: правило, путь и строка."""
    project = _project()
    scan = _scan(project)
    records = [
        _record(scan, 1, severity=Severity.CRITICAL),
        _record(scan, 2, severity=Severity.LOW, state=FindingState.EXISTING),
        _record(scan, 3, severity=Severity.MEDIUM, excluded=True),
    ]

    html = render_html(_report(project=project, records=records))

    for record in records:
        assert record.rule_id in html
        assert f"<code>{record.path}</code>" in html
        assert f">{record.line}</td>" in html
    assert "Находки — 3" in html
    assert "Новых: 2, существующих: 1" in html


def test_fr_008_html_marks_blocking_finding() -> None:
    """Блокирующая находка — новая `critical` при пороге `critical` — видна в HTML."""
    project = _project()
    scan = _scan(project, verdict=Verdict.FAIL)
    records = [_record(scan, 1, severity=Severity.CRITICAL)]

    report = _report(project=project, records=records, verdict=Verdict.FAIL)
    html = render_html(report)

    assert report.findings[0].blocking is True
    assert "блокирует" in html
    assert report.scan.verdict == Verdict.FAIL


# --- FR-015: пять метрик в отчёте --------------------------------------------------


def test_fr_015_report_contains_all_five_metrics() -> None:
    """FR-015: все пять величин есть и в JSON, и в HTML."""
    report = _report(fixed=2)
    payload = json.loads(render_json(report))
    metrics = payload["metrics"]

    assert set(metrics) == {
        "duration_sec",
        "findings_by_severity",
        "new",
        "fixed",
        "excluded_ratio",
    }
    assert set(metrics["findings_by_severity"]) == set(SEVERITY_KEYS)
    assert metrics["fixed"] == 2

    html = render_html(report)
    for label in (
        "Длительность",
        "Новые находки",
        "Исправленные находки",
        "Доля исключённых",
        "Находки по важности",
    ):
        assert label in html


# --- FR-013, S-004: деградация проверки -------------------------------------------


def test_fr_013_degraded_check_is_visible_in_report() -> None:
    """Упавший сканер попадает в отчёт с причиной и предупреждением о покрытии."""
    runs = [
        _run("semgrep"),
        _run("gitleaks", status=ScannerStatus.FAILED, error="Инструмент завершился с кодом 1"),
        _run("trivy"),
    ]

    report = _report(runs=runs)
    html = render_html(report)

    failed = next(check for check in report.checks if check.scanner == "gitleaks")
    assert failed.degraded is True
    assert failed.status is ScannerStatus.FAILED
    assert report.totals.degraded_checks == 1
    assert "Покрытие неполное" in html
    assert "Инструмент завершился с кодом 1" in html


# --- FR-008: артефакты на диске ---------------------------------------------------


def test_fr_008_two_artifact_files_are_written(tmp_path: Path) -> None:
    """Оба файла лежат в каталоге рядом: `<scan_id>.json` и `<scan_id>.html`."""
    project = _project()
    scan = _scan(project)
    records = [_record(scan, 1, severity=Severity.CRITICAL)]
    directory = tmp_path / "reports"

    paths = save_reports(
        scan,
        project,
        records,
        _metrics(records),
        [_run()],
        [Severity.CRITICAL],
        directory=directory,
    )

    assert paths.json_path == directory / f"{scan.id}.json"
    assert paths.html_path == directory / f"{scan.id}.html"
    payload = json.loads(paths.json_path.read_text(encoding="utf-8"))
    assert payload["scan"]["id"] == str(scan.id)
    assert payload["totals"]["blocking"] == 1
    html = paths.html_path.read_text(encoding="utf-8")
    assert html.startswith("<!DOCTYPE html>")
    assert "<code>rule-1</code>" in html


# --- Интеграционные: конвейер пишет отчёты -----------------------------------------


class _SarifAdapter:
    """Адаптер без инструмента: пишет SARIF в каталог артефактов и возвращает `ok`."""

    def __init__(self, name: str, *results: dict[str, object]) -> None:
        self.name = name
        self.results = results

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        document = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": self.name}}, "results": list(self.results)}],
        }
        path = output_dir / f"{self.name}.sarif"
        path.write_text(json.dumps(document), encoding="utf-8")
        return ScannerRun(
            scanner=self.name,
            status=ScannerStatus.OK,
            duration_ms=0,
            sarif_path=path,
            tool_version="test",
        )


def _result(rule_id: str, severity: str) -> dict[str, object]:
    """Один result SARIF с важностью в `properties.severity`."""
    return {
        "ruleId": rule_id,
        "message": {"text": f"Находка {rule_id}"},
        "properties": {"severity": severity},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/app.py"},
                    "region": {"startLine": 3},
                }
            }
        ],
    }


def _clone(repo_url: str, commit_sha: str, workdir: Path) -> None:
    """Фейковый клон: каталог с одним файлом, git не нужен."""
    assert repo_url and commit_sha
    (workdir / "src").mkdir(parents=True)
    (workdir / "src" / "app.py").write_text("print('demo')\n", encoding="utf-8")


def _queued_scan(session: Session) -> Scan:
    """Проект с адресом репозитория и прогон в очереди."""
    project = Project(
        name="Демо",
        slug=f"reports-{uuid.uuid4().hex[:8]}",
        repo_url="https://example.test/demo.git",
    )
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, commit_sha=SHA, ref="refs/heads/main", provider="github")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _execute(scan: Scan, session: Session, workspace: Path, reports_dir: Path) -> None:
    """Прогон по тестовой сессии: `queued → running`, конвейер, отчёты в каталог."""
    mark_running(session, scan)
    execute_scan(
        str(scan.id),
        session_scope=lambda: nullcontext(session),
        adapters=[
            _SarifAdapter("semgrep", _result("rule-sast", "medium")),
            _SarifAdapter("gitleaks"),
            _SarifAdapter("trivy"),
        ],
        clone=_clone,
        workspace=workspace,
        reports_dir=reports_dir,
    )


@pytest.mark.integration
def test_fr_008_pipeline_writes_report_artifacts(db_session: Session, tmp_path: Path) -> None:
    """Прогон из очереди оставляет рядом с вердиктом два файла отчёта."""
    scan = _queued_scan(db_session)
    directory = tmp_path / "reports"

    _execute(scan, db_session, tmp_path / "work", directory)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.PASS
    json_path = directory / f"{scan.id}.json"
    html_path = directory / f"{scan.id}.html"
    assert json_path.is_file() and html_path.is_file()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["scan"]["verdict"] == "pass"
    assert payload["metrics"]["new"] == 1
    assert payload["totals"]["findings"] == 1
    assert payload["checks"][0]["scanner"] == "semgrep"

    html = html_path.read_text(encoding="utf-8")
    assert "rule-sast" in html
    assert "src/app.py" in html


@pytest.mark.integration
def test_fr_008_report_failure_keeps_scan_done(
    db_session: Session, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Сбой записи отчёта — предупреждение в лог; прогон остаётся `done` с вердиктом."""
    scan = _queued_scan(db_session)
    # Каталог отчётов занят файлом: mkdir падает с OSError, прогон — нет.
    blocked = tmp_path / "reports"
    blocked.write_text("не каталог", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger=PIPELINE_LOGGER):
        _execute(scan, db_session, tmp_path / "work", blocked)

    assert scan.status == ScanStatus.DONE
    assert scan.verdict == Verdict.PASS
    assert any("отчёты не записаны" in record.message for record in caplog.records)
    assert not blocked.is_dir()
