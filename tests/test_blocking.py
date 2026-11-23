"""Блокировка по новой находке блокирующего уровня (T-018, FR-005, S-002).

Сценарий S-002: политика проекта блокирует `critical`, сканер находит новую
`critical` — прогон получает `fail`, и по этому вердикту CI завершается
ненулевым кодом (код выхода проверен в `tests/test_cli.py`, FR-033).

Чистые тесты проверяют `blocking_findings` и `compute_verdict` без базы:
в список попадают только новые неисключённые находки уровней из политики,
а `existing`, `excluded` и уровни ниже порога не попадают. Интеграционные —
тот же сценарий на строках `findings`/`scans`: вердикт пишется в
`scans.verdict`, а список блокирующих находок даёт правило, файл и строку —
их покажет отчёт (T-020).

`tests/test_policy.py` уже проверяет умолчание `critical`+`high`, пороги по
проектам и видимость вердикта в API. Здесь этого нет: упор на явную политику
`critical` из S-002 и на состав списка блокирующих находок.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.auth import service as auth_service
from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.baseline import install_baseline
from patches_please.policy.classify import FindingState, classify
from patches_please.policy.exceptions import create_exception
from patches_please.policy.verdict import (
    Verdict,
    apply_exceptions,
    blocking_findings,
    compute_verdict,
    save_verdict,
    upsert_policy,
)
from patches_please.projects.models import Project
from patches_please.scans.findings import save_findings
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import mark_done, mark_running

PASSWORD = "пароль-123"
SHA = "b" * 40


def _finding(
    index: int,
    *,
    severity: Severity,
    rule_id: str | None = None,
    path: str | None = None,
    line: int = 1,
) -> Finding:
    """Находка с уникальным fingerprint: путь и правило зависят от индекса."""
    rule = rule_id or f"rule-{index}"
    location = path or f"src/module_{index}.py"
    return Finding(
        scanner="semgrep",
        rule_id=rule,
        severity=severity,
        path=location,
        line=line,
        message=f"Находка {rule}",
        finding_type=FindingType.SAST,
        fingerprint=compute_fingerprint("semgrep", rule, location, f"dangerous_call({index})"),
    )


def _record(
    *,
    severity: Severity,
    state: FindingState = FindingState.NEW,
    excluded: bool = False,
    rule_id: str = "rule-1",
    path: str = "src/app.py",
    line: int = 1,
) -> FindingRecord:
    """Несохранённая строка находки для чистой проверки вердикта."""
    return FindingRecord(
        scan_id=uuid.uuid4(),
        fingerprint="f" * 64,
        scanner="semgrep",
        rule_id=rule_id,
        finding_type=str(FindingType.SAST),
        severity=str(severity),
        path=path,
        line=line,
        message="Опасный вызов",
        state=str(state),
        excluded=excluded,
    )


def _project(session: Session) -> Project:
    project = Project(name="Демо", slug=f"demo-{uuid.uuid4().hex[:8]}")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _queued_scan(session: Session, project: Project) -> Scan:
    """Прогон в статусе `queued`: проект нужен ради внешнего ключа."""
    scan = Scan(project_id=project.id, commit_sha=SHA, ref="refs/heads/main", provider="github")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _done_scan(session: Session, project: Project) -> Scan:
    scan = _queued_scan(session, project)
    mark_running(session, scan)
    mark_done(session, scan)
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


def _scan_records(session: Session, scan: Scan) -> list[FindingRecord]:
    """Находки прогона в том же порядке, что читает вердикт."""
    statement = (
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan.id)
        .order_by(FindingRecord.created_at, FindingRecord.id)
    )
    return list(session.scalars(statement))


# --- FR-005, S-002: что именно блокирует -----------------------------------------


def test_fr_005_s002_new_critical_is_blocking() -> None:
    """Новая `critical` при политике `critical` попадает в блокирующие и даёт `fail`."""
    record = _record(severity=Severity.CRITICAL)

    assert blocking_findings([record], {Severity.CRITICAL}) == [record]
    assert compute_verdict([record], {Severity.CRITICAL}) is Verdict.FAIL


def test_fr_005_s002_medium_is_below_threshold() -> None:
    """Находка ниже порога политики не блокирует."""
    record = _record(severity=Severity.MEDIUM)

    assert blocking_findings([record], {Severity.CRITICAL}) == []
    assert compute_verdict([record], {Severity.CRITICAL}) is Verdict.PASS


def test_fr_005_s002_existing_critical_is_not_blocking() -> None:
    """Находка из baseline — `existing`, вердикт не меняет (FR-006)."""
    record = _record(severity=Severity.CRITICAL, state=FindingState.EXISTING)

    assert blocking_findings([record], {Severity.CRITICAL}) == []
    assert compute_verdict([record], {Severity.CRITICAL}) is Verdict.PASS


def test_fr_005_s002_excluded_critical_is_not_blocking() -> None:
    """Находка под действующим исключением не блокирует (FR-011)."""
    record = _record(severity=Severity.CRITICAL, excluded=True)

    assert blocking_findings([record], {Severity.CRITICAL}) == []
    assert compute_verdict([record], {Severity.CRITICAL}) is Verdict.PASS


def test_fr_005_s002_blocking_list_contains_only_blocking_findings() -> None:
    """Смешанный прогон: в списке ровно новые неисключённые находки из политики."""
    blocking = _record(severity=Severity.CRITICAL, rule_id="rule-blocking")
    records = [
        blocking,
        _record(severity=Severity.MEDIUM, rule_id="rule-medium"),
        _record(severity=Severity.CRITICAL, state=FindingState.EXISTING),
        _record(severity=Severity.CRITICAL, excluded=True),
    ]

    assert blocking_findings(records, {Severity.CRITICAL}) == [blocking]
    assert compute_verdict(records, {Severity.CRITICAL}) is Verdict.FAIL


def test_fr_005_s002_blocking_follows_project_policy() -> None:
    """Одна и та же `high` блокирует только там, где порог её включает (FR-014)."""
    record = _record(severity=Severity.HIGH)

    assert blocking_findings([record], {Severity.CRITICAL}) == []
    assert compute_verdict([record], {Severity.CRITICAL}) is Verdict.PASS
    assert blocking_findings([record], {Severity.CRITICAL, Severity.HIGH}) == [record]
    assert compute_verdict([record], {Severity.CRITICAL, Severity.HIGH}) is Verdict.FAIL


# --- FR-005, S-002: вердикт и список блокирующих находок на сохранённом прогоне ---


@pytest.mark.integration
def test_fr_005_s002_new_critical_scan_gets_fail(db_session: Session) -> None:
    """Политика `critical` + новая `critical`: вердикт `fail`, в списке правило, файл, строка."""
    project = _project(db_session)
    upsert_policy(db_session, project.id, block_severities=[Severity.CRITICAL])
    finding = _finding(
        0,
        severity=Severity.CRITICAL,
        rule_id="python.lang.security.audit.eval",
        path="src/app.py",
        line=42,
    )
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [finding])

    assert save_verdict(db_session, scan) is Verdict.FAIL
    assert scan.verdict == "fail"

    blocking = blocking_findings(_scan_records(db_session, scan), {Severity.CRITICAL})
    assert [(record.rule_id, record.path, record.line) for record in blocking] == [
        ("python.lang.security.audit.eval", "src/app.py", 42)
    ]


@pytest.mark.integration
def test_fr_005_s002_medium_scan_gets_pass(db_session: Session) -> None:
    """Политика `critical` + только `medium`: вердикт `pass`, блокирующих нет."""
    project = _project(db_session)
    upsert_policy(db_session, project.id, block_severities=[Severity.CRITICAL])
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0, severity=Severity.MEDIUM)])

    assert save_verdict(db_session, scan) is Verdict.PASS
    assert scan.verdict == "pass"
    assert blocking_findings(_scan_records(db_session, scan), {Severity.CRITICAL}) == []


@pytest.mark.integration
def test_fr_005_s002_baseline_and_exception_do_not_block(db_session: Session) -> None:
    """`existing` из baseline и `excluded` по исключению не блокируют даже при `critical`."""
    project = _project(db_session)
    upsert_policy(db_session, project.id, block_severities=[Severity.CRITICAL])
    author = auth_service.create_user(db_session, "author@example.com", PASSWORD)
    historical = _finding(0, severity=Severity.CRITICAL, path="src/legacy.py")
    suppressed = _finding(1, severity=Severity.CRITICAL, path="src/false_positive.py")

    baseline_scan = _done_scan(db_session, project)
    _store(db_session, baseline_scan, [historical])
    install_baseline(db_session, baseline_scan)
    create_exception(
        db_session,
        project_id=project.id,
        rule_id=suppressed.rule_id,
        path_glob="src/*.py",
        reason="ложное срабатывание",
        author_id=author.id,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )

    scan = _done_scan(db_session, project)
    _store(db_session, scan, [historical, suppressed], base=[historical.fingerprint])
    assert apply_exceptions(db_session, scan) == 1

    records = _scan_records(db_session, scan)
    historical_record = next(record for record in records if record.rule_id == historical.rule_id)
    suppressed_record = next(record for record in records if record.rule_id == suppressed.rule_id)
    assert historical_record.state == str(FindingState.EXISTING)
    assert suppressed_record.state == str(FindingState.NEW)
    assert suppressed_record.excluded is True
    assert blocking_findings(records, {Severity.CRITICAL}) == []
    assert save_verdict(db_session, scan) is Verdict.PASS
    assert scan.verdict == "pass"
