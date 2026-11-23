"""База сравнения и метки находок (T-014, FR-006, FR-016, FR-038).

Проверяется выбор базы «baseline → предыдущий `done`-прогон → пустой набор»,
идемпотентность установки baseline и классификация `new`/`existing`/`fixed`.
Чистые тесты работают на доменных находках без базы, интеграционные идут через
`db_session` с откатываемой транзакцией — как в `tests/test_status.py`.

Сценарий S-003 проверяется на уровне классификации: 300 исторических находок,
зафиксированных baseline, остаются `existing`, новых нет.
"""

import uuid
from datetime import datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.baseline import (
    BaselineError,
    BaselineSource,
    install_baseline,
    resolve_base,
)
from patches_please.policy.classify import FindingState, classify
from patches_please.policy.models import Baseline, BaselineItem
from patches_please.projects.models import Project
from patches_please.scans.findings import load_findings, save_findings
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import mark_done, mark_error, mark_running

SHA = "a" * 40


def _finding(index: int, *, line: int = 1) -> Finding:
    """Находка с уникальным fingerprint: путь и правило зависят от индекса."""
    rule_id = f"rule-{index}"
    path = f"src/module_{index}.py"
    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        severity=Severity.HIGH,
        path=path,
        line=line,
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


def _scan(session: Session, project: Project) -> Scan:
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


def _set_started_at(session: Session, scan: Scan, started_at: datetime) -> None:
    """Фиксирует время начала: порядок прогонов в тесте не зависит от часов."""
    scan.started_at = started_at
    session.commit()


def _done_scan(session: Session, project: Project, *, started_at: datetime | None = None) -> Scan:
    scan = _scan(session, project)
    mark_running(session, scan)
    mark_done(session, scan)
    if started_at is not None:
        _set_started_at(session, scan, started_at)
    return scan


def _error_scan(session: Session, project: Project, *, started_at: datetime | None = None) -> Scan:
    scan = _scan(session, project)
    mark_running(session, scan)
    mark_error(session, scan, "сканер упал")
    if started_at is not None:
        _set_started_at(session, scan, started_at)
    return scan


def _store(session: Session, scan: Scan, findings: list[Finding]) -> list[FindingRecord]:
    """Сохраняет находки прогона без базы: все находки новые."""
    return save_findings(session, scan, classify(findings, []))


def _item_fingerprints(session: Session, baseline: Baseline) -> set[str]:
    statement = select(BaselineItem.fingerprint).where(BaselineItem.baseline_id == baseline.id)
    return set(session.scalars(statement))


# --- FR-006: baseline не даёт заблокировать исторический шум (S-003) ---------------


def test_fr_006_baseline_of_300_findings_marks_all_existing() -> None:
    """S-003: 300 исторических находок в baseline — все `existing`, новых нет."""
    findings = [_finding(index) for index in range(300)]
    assert len({finding.fingerprint for finding in findings}) == 300

    result = classify(findings, [finding.fingerprint for finding in findings])

    assert len(result.findings) == 300
    assert all(item.state is FindingState.EXISTING for item in result.findings)
    assert result.new_count == 0
    assert result.existing_count == 300
    assert result.fixed == ()


@pytest.mark.integration
def test_fr_006_install_baseline_snapshots_selected_scan(db_session: Session) -> None:
    """Baseline фиксирует fingerprints выбранного прогона, а не проекта целиком."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    findings = [_finding(index) for index in range(3)]
    _store(db_session, scan, findings)

    baseline = install_baseline(db_session, scan)

    assert baseline.project_id == project.id
    assert baseline.scan_id == scan.id
    assert _item_fingerprints(db_session, baseline) == {finding.fingerprint for finding in findings}


@pytest.mark.integration
def test_fr_006_repeated_install_is_idempotent(db_session: Session) -> None:
    """Повторная установка тем же прогоном не меняет id, набор и число элементов."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0), _finding(1)])

    first = install_baseline(db_session, scan)
    first_id = first.id
    first_items = _item_fingerprints(db_session, first)

    second = install_baseline(db_session, scan)

    assert second.id == first_id
    assert _item_fingerprints(db_session, second) == first_items
    assert len(_item_fingerprints(db_session, second)) == len(first_items)


@pytest.mark.integration
def test_fr_006_baseline_takes_precedence_over_previous_scan(db_session: Session) -> None:
    """Установленный baseline важнее более свежего предыдущего прогона."""
    project = _project(db_session)
    baseline_scan = _done_scan(db_session, project, started_at=datetime(2026, 1, 1))
    baseline_findings = [_finding(0), _finding(1)]
    _store(db_session, baseline_scan, baseline_findings)
    install_baseline(db_session, baseline_scan)

    newer_scan = _done_scan(db_session, project, started_at=datetime(2026, 1, 2))
    _store(db_session, newer_scan, [_finding(0), _finding(2)])

    base = resolve_base(db_session, project.id)

    assert base.source is BaselineSource.BASELINE
    assert base.scan_id == baseline_scan.id
    assert base.fingerprints == {finding.fingerprint for finding in baseline_findings}


# --- FR-016: классификация относительно предыдущего прогона -----------------------


def test_fr_016_new_existing_fixed_on_two_consecutive_runs() -> None:
    """Общая находка `existing`, появившаяся `new`, исчезнувшая `fixed`."""
    common, disappeared, appeared = _finding(0), _finding(1), _finding(2)
    first_run = [common, disappeared]
    second_run = [common, appeared]

    result = classify(second_run, [finding.fingerprint for finding in first_run])

    states = {item.finding.fingerprint: item.state for item in result.findings}
    assert states[common.fingerprint] is FindingState.EXISTING
    assert states[appeared.fingerprint] is FindingState.NEW
    assert result.fixed == (disappeared.fingerprint,)
    assert (result.new_count, result.existing_count, result.fixed_count) == (1, 1, 1)


def test_fr_016_empty_baseline_marks_all_new() -> None:
    """Первый прогон проекта: базы нет, все находки новые, исправленных нет."""
    result = classify([_finding(0), _finding(1)], [])

    assert all(item.state is FindingState.NEW for item in result.findings)
    assert result.existing_count == 0
    assert result.fixed == ()


def test_fr_016_disappeared_finding_is_fixed() -> None:
    """Fingerprint базы, которого нет в прогоне, попадает в `fixed`."""
    present, disappeared = _finding(0), _finding(1)

    result = classify([present], [present.fingerprint, disappeared.fingerprint])

    assert result.fixed == (disappeared.fingerprint,)
    assert result.new_count == 0
    assert result.existing_count == 1


@pytest.mark.integration
def test_fr_016_previous_done_scan_is_fallback(db_session: Session) -> None:
    """Без baseline база — предыдущий `done`-прогон; прогон в `error` базой не становится."""
    project = _project(db_session)
    done_scan = _done_scan(db_session, project, started_at=datetime(2026, 1, 1))
    done_findings = [_finding(0), _finding(1)]
    _store(db_session, done_scan, done_findings)

    error_scan = _error_scan(db_session, project, started_at=datetime(2026, 1, 2))
    _store(db_session, error_scan, [_finding(2)])

    current_scan = _done_scan(db_session, project, started_at=datetime(2026, 1, 3))
    _store(db_session, current_scan, [_finding(3)])

    base = resolve_base(db_session, project.id, current_scan_id=current_scan.id)

    assert base.source is BaselineSource.PREVIOUS_SCAN
    assert base.scan_id == done_scan.id
    assert base.fingerprints == {finding.fingerprint for finding in done_findings}

    # Без исключения текущего прогона базой становится он сам: свежий `done`.
    latest = resolve_base(db_session, project.id)

    assert latest.scan_id == current_scan.id


@pytest.mark.integration
def test_fr_016_no_baseline_and_no_previous_scan_is_empty(db_session: Session) -> None:
    """Ни baseline, ни предыдущего прогона — пустая база, а не ошибка."""
    project = _project(db_session)

    snapshot = resolve_base(db_session, project.id)

    assert snapshot.source is BaselineSource.NONE
    assert snapshot.scan_id is None
    assert snapshot.fingerprints == frozenset()


# --- FR-038: порядок, дедупликация и границы установки ----------------------------


def test_fr_038_order_and_dedup_within_run_preserved() -> None:
    """Дубль fingerprint схлопывается в первое вхождение, порядок остальных сохранён."""
    first, second, third = _finding(0), _finding(1), _finding(2)
    duplicate = _finding(0, line=99)

    result = classify([first, second, duplicate, third], [])

    assert [item.finding.fingerprint for item in result.findings] == [
        first.fingerprint,
        second.fingerprint,
        third.fingerprint,
    ]
    assert result.findings[0].finding is first


def test_fr_038_fixed_fingerprints_are_sorted() -> None:
    """Список `fixed` отсортирован: у множества нет собственного порядка."""
    base = ["ff" * 32, "aa" * 32, "cc" * 32, "bb" * 32]

    result = classify([], base)

    assert result.fixed == tuple(sorted(base))
    assert result.fixed_count == 4


@pytest.mark.integration
def test_fr_038_baseline_rejects_not_done_scan(db_session: Session) -> None:
    """Незавершённый прогон в baseline не попадает: набор был бы неполным."""
    project = _project(db_session)
    scan = _scan(db_session, project)
    mark_running(db_session, scan)

    with pytest.raises(BaselineError, match="завершённому прогону"):
        install_baseline(db_session, scan)

    assert db_session.scalar(select(Baseline)) is None


@pytest.mark.integration
def test_fr_038_save_findings_persists_state(db_session: Session) -> None:
    """Метки `new`/`existing` пишутся в БД, повторное сохранение не плодит строки."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    known, appeared = _finding(0), _finding(1)
    result = classify([known, appeared], [known.fingerprint])

    save_findings(db_session, scan, result)

    stored = {
        record.fingerprint: record.state
        for record in db_session.scalars(
            select(FindingRecord).where(FindingRecord.scan_id == scan.id)
        )
    }
    assert stored == {known.fingerprint: "existing", appeared.fingerprint: "new"}

    save_findings(db_session, scan, result)

    count = db_session.scalar(
        select(func.count()).select_from(FindingRecord).where(FindingRecord.scan_id == scan.id)
    )
    assert count == 2
    assert {finding.fingerprint for finding in load_findings(db_session, scan.id)} == set(stored)
