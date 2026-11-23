"""Метрики завершённого прогона (T-016, FR-015).

Проверяются все пять величин: длительность из `started_at`/`finished_at`,
находки по пяти уровням severity, новые и исправленные по базе сравнения,
доля исключённых с делением на ноль на пустом прогоне, отказ для
незавершённого прогона и чтение метрик из `scans.timings` обратно.

Интеграционные тесты идут через `db_session` с откатываемой транзакцией —
как в `tests/test_baseline.py`. До T-017 флаг `excluded` в рабочем коде не
поднимается, поэтому тест доли исключённых выставляет его напрямую.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.metrics.service import (
    MetricsError,
    compute_metrics,
    load_metrics,
    save_metrics,
)
from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.baseline import install_baseline
from patches_please.policy.classify import classify
from patches_please.projects.models import Project
from patches_please.scans.findings import save_findings
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import mark_done, mark_running

SHA = "b" * 40
START = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
SEVERITY_KEYS = {"critical", "high", "medium", "low", "info"}


def _finding(index: int, *, severity: Severity = Severity.HIGH) -> Finding:
    """Находка с уникальным fingerprint: путь и правило зависят от индекса."""
    rule_id = f"rule-{index}"
    path = f"src/module_{index}.py"
    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=1,
        message=f"Находка {rule_id}",
        finding_type=FindingType.SAST,
        fingerprint=compute_fingerprint("semgrep", rule_id, path, f"dangerous_call({index})"),
    )


def _project(session: Session) -> Project:
    project = Project(name="Демо", slug=f"demo-{uuid.uuid4().hex[:8]}")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _queued_scan(session: Session, project: Project) -> Scan:
    """Прогон в статусе `queued`: проект нужен ради внешнего ключа."""
    scan = Scan(
        project_id=project.id,
        commit_sha=SHA,
        ref="refs/heads/main",
        provider="github",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _set_times(session: Session, scan: Scan, started_at: datetime, duration_sec: float) -> None:
    """Подменяет время прогона: длительность в тесте не зависит от часов машины."""
    scan.started_at = started_at
    scan.finished_at = started_at + timedelta(seconds=duration_sec)
    session.commit()


def _done_scan(
    session: Session,
    project: Project,
    *,
    started_at: datetime = START,
    duration_sec: float = 0.0,
) -> Scan:
    scan = _queued_scan(session, project)
    mark_running(session, scan)
    mark_done(session, scan)
    _set_times(session, scan, started_at, duration_sec)
    return scan


def _store(
    session: Session,
    scan: Scan,
    findings: list[Finding],
    *,
    base: list[str] | None = None,
) -> list[FindingRecord]:
    """Сохраняет находки прогона; без базы все находки новые."""
    return save_findings(session, scan, classify(findings, base or []))


def _exclude(session: Session, scan: Scan, finding: Finding) -> None:
    """Поднимает `excluded` у находки напрямую: связку с вердиктом делает T-017."""
    record = session.scalar(
        select(FindingRecord).where(
            FindingRecord.scan_id == scan.id,
            FindingRecord.fingerprint == finding.fingerprint,
        )
    )
    assert record is not None
    record.excluded = True
    session.commit()


# --- FR-015: длительность ---------------------------------------------------------


@pytest.mark.integration
def test_fr_015_duration_is_finish_minus_start(db_session: Session) -> None:
    """Длительность — разница времени начала и завершения в секундах."""
    project = _project(db_session)
    scan = _done_scan(db_session, project, duration_sec=90.0)

    metrics = compute_metrics(db_session, scan)

    assert metrics.duration_sec == pytest.approx(90.0)


# --- FR-015: находки по severity --------------------------------------------------


@pytest.mark.integration
def test_fr_015_findings_counted_by_every_severity(db_session: Session) -> None:
    """Считаются все пять уровней шкалы, повтор одного уровня суммируется."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    _store(
        db_session,
        scan,
        [
            _finding(0, severity=Severity.CRITICAL),
            _finding(1, severity=Severity.HIGH),
            _finding(2, severity=Severity.HIGH),
            _finding(3, severity=Severity.MEDIUM),
            _finding(4, severity=Severity.LOW),
            _finding(5, severity=Severity.INFO),
        ],
    )

    metrics = compute_metrics(db_session, scan)

    assert metrics.findings_by_severity == {
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "info": 1,
    }


@pytest.mark.integration
def test_fr_015_empty_run_has_all_severity_keys_with_zero(db_session: Session) -> None:
    """Пустой прогон отдаёт все пять ключей с нулями, а не пустой словарь."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)

    metrics = compute_metrics(db_session, scan)

    assert set(metrics.findings_by_severity) == SEVERITY_KEYS
    assert set(metrics.findings_by_severity.values()) == {0}


# --- FR-015: новые и исправленные -------------------------------------------------


@pytest.mark.integration
def test_fr_015_new_and_fixed_against_previous_scan(db_session: Session) -> None:
    """`new` берётся из метки находки, `fixed` — из fingerprints базы."""
    project = _project(db_session)
    previous = _done_scan(db_session, project, started_at=START)
    disappeared, common = _finding(0), _finding(1)
    _store(db_session, previous, [disappeared, common])

    current = _done_scan(db_session, project, started_at=START + timedelta(hours=1))
    appeared = _finding(2)
    _store(
        db_session,
        current,
        [common, appeared],
        base=[disappeared.fingerprint, common.fingerprint],
    )

    metrics = compute_metrics(db_session, current)

    assert metrics.new == 1
    assert metrics.fixed == 1
    assert sum(metrics.findings_by_severity.values()) == 2


@pytest.mark.integration
def test_fr_015_fixed_counted_against_baseline(db_session: Session) -> None:
    """Установленный baseline важнее предыдущего прогона и при расчёте метрик."""
    project = _project(db_session)
    baseline_scan = _done_scan(db_session, project, started_at=START)
    disappeared, common = _finding(0), _finding(1)
    _store(db_session, baseline_scan, [disappeared, common])
    install_baseline(db_session, baseline_scan)

    current = _done_scan(db_session, project, started_at=START + timedelta(hours=1))
    _store(
        db_session,
        current,
        [common],
        base=[disappeared.fingerprint, common.fingerprint],
    )

    metrics = compute_metrics(db_session, current)

    assert metrics.new == 0
    assert metrics.fixed == 1


@pytest.mark.integration
def test_fr_015_first_run_has_no_fixed_findings(db_session: Session) -> None:
    """Первый прогон проекта: базы нет, все находки новые, исправленных нет."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0), _finding(1)])

    metrics = compute_metrics(db_session, scan)

    assert metrics.new == 2
    assert metrics.fixed == 0


# --- FR-015: доля исключённых -----------------------------------------------------


@pytest.mark.integration
def test_fr_015_excluded_ratio_is_share_of_run_findings(db_session: Session) -> None:
    """Доля исключённых — исключённые ко всем находкам прогона."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    excluded = _finding(0)
    _store(db_session, scan, [excluded, _finding(1), _finding(2), _finding(3)])
    _exclude(db_session, scan, excluded)

    metrics = compute_metrics(db_session, scan)

    assert metrics.excluded_ratio == pytest.approx(0.25)


@pytest.mark.integration
def test_fr_015_excluded_ratio_is_zero_for_empty_run(db_session: Session) -> None:
    """Пустой прогон: знаменателя нет, доля равна нулю без деления на ноль."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)

    metrics = compute_metrics(db_session, scan)

    assert metrics.excluded_ratio == 0.0


# --- FR-015: сохранение и чтение --------------------------------------------------


@pytest.mark.integration
def test_fr_015_save_metrics_persists_and_loads_back(db_session: Session) -> None:
    """Метрики пишутся в `scans.timings` и читаются обратно после перезагрузки."""
    project = _project(db_session)
    scan = _done_scan(db_session, project, duration_sec=12.5)
    _store(db_session, scan, [_finding(0), _finding(1)])

    saved = save_metrics(db_session, scan)
    db_session.expire_all()
    reloaded = db_session.get(Scan, scan.id)
    assert reloaded is not None

    assert set(reloaded.timings or {}) == {
        "duration_sec",
        "findings_by_severity",
        "new",
        "fixed",
        "excluded_ratio",
    }
    assert load_metrics(reloaded) == saved
    assert saved.duration_sec == pytest.approx(12.5)
    assert saved.new == 2


@pytest.mark.integration
def test_fr_015_load_metrics_without_saved_values_raises(db_session: Session) -> None:
    """Прогон без сохранённых метрик не выдаёт нули: это ошибка, а не результат."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)

    with pytest.raises(MetricsError, match="нет сохранённых метрик"):
        load_metrics(scan)


# --- FR-015: границы расчёта ------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize("status", ["queued", "running"])
def test_fr_015_rejects_unfinished_scan(db_session: Session, status: str) -> None:
    """Незавершённый прогон метрик не даёт: времени завершения ещё нет."""
    project = _project(db_session)
    scan = _queued_scan(db_session, project)
    if status == "running":
        mark_running(db_session, scan)

    with pytest.raises(MetricsError, match="только по завершённому прогону"):
        compute_metrics(db_session, scan)


@pytest.mark.integration
def test_fr_015_rejects_done_scan_without_start_time(db_session: Session) -> None:
    """Прогон без времени начала отклоняется: длительность не определена."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    scan.started_at = None
    db_session.commit()

    with pytest.raises(MetricsError, match="времени начала"):
        compute_metrics(db_session, scan)
