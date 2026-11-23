"""JSON-отчёт завершённого прогона (T-020, FR-008, FR-015).

Отчёт собирается из того, что уже сохранено: строка `scans` с вердиктом,
проект, находки прогона (`findings`), метрики `scans.timings` (FR-015) и итоги
запусков сканеров (`ScannerRun`). Своих данных отчёт не заводит — только
упорядочивает сохранённое для человека и для машинного чтения.

Схема отчёта — `ScanReport`: источник правды для `contracts/report.schema.json`.
Файл генерируется из модели (`uv run python -m scripts.export_report_schema`) и
сверяется тестом. Новых зависимостей нет: «JSON валиден по схеме» значит, что
записанный JSON разбирается той же моделью без ошибок, а файл схемы совпадает с
моделью.

Находки с `state=new`, не исключённые и уровня из политики проекта помечаются
`blocking` — это причина вердикта `fail` (FR-005). Пометка считается тем же
предикатом `blocking_findings`, что и сам вердикт, поэтому отчёт и вердикт не
расходятся.

Содержимое находок попадает только в файл отчёта и не пишется в лог:
маскирование секретов — T-021, а новых путей утечки T-020 не добавляет
(NFR-004).
"""

import json
import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, Field

from patches_please.metrics.service import RunMetrics
from patches_please.normalize.model import FindingType, Severity
from patches_please.policy.classify import FindingState
from patches_please.policy.degraded import is_degraded
from patches_please.policy.verdict import Verdict, blocking_findings
from patches_please.projects.models import Project
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus

# Версия формата отчёта: меняется вместе со схемой, если поле убрали или
# переименовали. Новые необязательные поля версию не поднимают.
SCHEMA_VERSION: Final = "1"


class ReportError(ValueError):
    """По прогону нельзя построить отчёт: он не завершён или неполон."""


class ReportProject(BaseModel):
    """Проект в шапке отчёта: имя читают люди, slug связывает с интерфейсом."""

    id: uuid.UUID
    name: str
    slug: str


class ReportScan(BaseModel):
    """Шапка прогона: что проверяли, когда и с каким вердиктом."""

    id: uuid.UUID
    project: ReportProject
    commit_sha: str
    ref: str
    provider: str
    status: ScanStatus
    verdict: Verdict
    created_at: datetime
    started_at: datetime
    finished_at: datetime


class ReportMetrics(BaseModel):
    """Пять метрик FR-015 в том же наборе, что и в `scans.timings`."""

    duration_sec: float
    findings_by_severity: dict[str, int]
    new: int
    fixed: int
    excluded_ratio: float


class ReportCheck(BaseModel):
    """Итог запуска одного сканера: статус, длительность, версия и причина.

    `degraded` — не третье значение вердикта (FR-004), а признак неполного
    покрытия проверки (FR-013, S-004): такой запуск в отчёте виден отдельно.
    """

    scanner: str
    status: ScannerStatus
    duration_ms: int
    tool_version: str | None = None
    error: str | None = None
    degraded: bool


class ReportFinding(BaseModel):
    """Находка прогона: поля FR-003 плюс классификация и решение по политике."""

    scanner: str
    rule_id: str
    finding_type: FindingType
    severity: Severity
    path: str
    line: int
    message: str
    state: FindingState
    excluded: bool
    blocking: bool


class ReportTotals(BaseModel):
    """Сводка по отчёту: по ней проверяют полноту, не пересчитывая находки."""

    findings: int
    new: int
    existing: int
    excluded: int
    blocking: int
    degraded_checks: int


class ScanReport(BaseModel):
    """Отчёт по завершённому прогону (FR-008): схема — источник правды."""

    schema_version: str = Field(default=SCHEMA_VERSION)
    scan: ReportScan
    metrics: ReportMetrics
    checks: list[ReportCheck]
    findings: list[ReportFinding]
    totals: ReportTotals


def build_report(
    scan: Scan,
    project: Project,
    records: Sequence[FindingRecord],
    metrics: RunMetrics,
    runs: Iterable[ScannerRun],
    block_severities: Iterable[Severity],
) -> ScanReport:
    """Собирает отчёт по завершённому прогону, не меняя данных.

    Находки берутся в порядке входа — том же, в каком их отдают
    `load_records` и метрики. Прогон вне статуса `done` отклоняется: у
    незавершённого нет ни вердикта, ни полного набора находок.
    """
    if ScanStatus(scan.status) is not ScanStatus.DONE:
        raise ReportError(
            f"Отчёт строится только по завершённому прогону, а он в статусе {scan.status}"
        )
    if scan.started_at is None or scan.finished_at is None:
        raise ReportError("У завершённого прогона нет времени начала или завершения")
    if scan.verdict is None:
        raise ReportError("У завершённого прогона нет вердикта")

    checks = [_check(run) for run in runs]
    blocking = {record.fingerprint for record in blocking_findings(records, block_severities)}
    findings = [_finding(record, blocking) for record in records]
    return ScanReport(
        scan=ReportScan(
            id=scan.id,
            project=ReportProject(id=project.id, name=project.name, slug=project.slug),
            commit_sha=scan.commit_sha,
            ref=scan.ref,
            provider=scan.provider,
            status=ScanStatus(scan.status),
            verdict=Verdict(scan.verdict),
            created_at=scan.created_at,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
        ),
        metrics=_metrics(metrics),
        checks=checks,
        findings=findings,
        totals=ReportTotals(
            findings=len(findings),
            new=sum(1 for finding in findings if finding.state is FindingState.NEW),
            existing=sum(1 for finding in findings if finding.state is FindingState.EXISTING),
            excluded=sum(1 for finding in findings if finding.excluded),
            blocking=sum(1 for finding in findings if finding.blocking),
            degraded_checks=sum(1 for check in checks if check.degraded),
        ),
    )


def render_json(report: ScanReport) -> str:
    """Отчёт как JSON: кириллица без escape, порядок полей — порядок схемы."""
    return json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"


def write_json(report: ScanReport, path: Path) -> None:
    """Пишет JSON-отчёт в файл целиком: частичный файл читателю не нужен."""
    path.write_text(render_json(report), encoding="utf-8", newline="\n")


def schema_document() -> dict[str, Any]:
    """JSON-схема отчёта из модели: её и хранит `contracts/report.schema.json`."""
    return ScanReport.model_json_schema()


def schema_json() -> str:
    """Схема в том виде, в каком она лежит в контракте: файл не правится вручную."""
    return json.dumps(schema_document(), ensure_ascii=False, indent=2) + "\n"


def _metrics(metrics: RunMetrics) -> ReportMetrics:
    """Метрики с полным набором уровней в порядке шкалы FR-014."""
    return ReportMetrics(
        duration_sec=metrics.duration_sec,
        findings_by_severity={
            str(severity): metrics.findings_by_severity[str(severity)] for severity in Severity
        },
        new=metrics.new,
        fixed=metrics.fixed,
        excluded_ratio=metrics.excluded_ratio,
    )


def _check(run: ScannerRun) -> ReportCheck:
    """Итог запуска сканера вместе с признаком деградации (FR-013)."""
    return ReportCheck(
        scanner=run.scanner,
        status=run.status,
        duration_ms=run.duration_ms,
        tool_version=run.tool_version,
        error=run.error,
        degraded=is_degraded(run),
    )


def _finding(record: FindingRecord, blocking: set[str]) -> ReportFinding:
    """Находка отчёта; `blocking` — по fingerprint, как в вердикте."""
    return ReportFinding(
        scanner=record.scanner,
        rule_id=record.rule_id,
        finding_type=FindingType(record.finding_type),
        severity=Severity(record.severity),
        path=record.path,
        line=record.line,
        message=record.message,
        state=FindingState(record.state),
        excluded=record.excluded,
        blocking=record.fingerprint in blocking,
    )
