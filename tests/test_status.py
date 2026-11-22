"""Жизненный цикл прогона: переходы статусов (T-009, FR-026).

Проверяется и доменный сервис, и задача воркера: допустимые переходы заполняют
время и причину, недопустимые отклоняются исключением, не трогая строку.
Интеграционные тесты идут на тестовой базе через `db_session`; воркер получает
область сессии с `nullcontext`, чтобы не открывать соединение к базе стенда.
"""

import logging
import uuid
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime

import pytest
from sqlalchemy.orm import Session

from app.projects.models import Project
from app.scans.models import Scan
from app.scans.queue import process_scan
from app.scans.service import (
    ALLOWED_TRANSITIONS,
    ScanStatus,
    ScanTransitionError,
    mark_done,
    mark_error,
    mark_running,
    transition,
)

SHA = "a" * 40
QUEUE_LOGGER = "app.scans.queue"

# Все пары статусов, которых нет в матрице переходов: каждая должна отклоняться.
INVALID_TRANSITIONS = [
    (current, target)
    for current in ScanStatus
    for target in ScanStatus
    if target not in ALLOWED_TRANSITIONS[current]
]


def _scan(session: Session) -> Scan:
    """Прогон в статусе `queued`: проект нужен только ради внешнего ключа."""
    project = Project(name="Демо", slug=f"demo-{uuid.uuid4().hex[:8]}")
    session.add(project)
    session.flush()
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


def _drive_to(session: Session, scan: Scan, status: ScanStatus) -> None:
    """Приводит прогон к нужному статусу штатными переходами."""
    if status is ScanStatus.QUEUED:
        return
    mark_running(session, scan)
    if status is ScanStatus.DONE:
        mark_done(session, scan)
    elif status is ScanStatus.ERROR:
        mark_error(session, scan, "сбой обработки")


def _apply(session: Session, scan: Scan, target: ScanStatus) -> None:
    """Вызывает переход в целевой статус без подготовки исходного."""
    reason = "сбой обработки" if target is ScanStatus.ERROR else None
    transition(session, scan, target, reason=reason)


def _unused_scope() -> AbstractContextManager[Session]:
    """Область сессии, которая не должна открываться: тест ловит лишний запрос."""
    raise AssertionError("сессия не должна открываться")


# --- Допустимые переходы ---------------------------------------------------------


@pytest.mark.integration
def test_fr_026_new_scan_is_queued(db_session: Session) -> None:
    scan = _scan(db_session)

    assert scan.status == ScanStatus.QUEUED
    assert scan.started_at is None
    assert scan.finished_at is None
    assert scan.error is None


@pytest.mark.integration
def test_fr_026_queued_to_running_sets_started_at(db_session: Session) -> None:
    scan = _scan(db_session)

    before = datetime.now(UTC)
    mark_running(db_session, scan)
    after = datetime.now(UTC)

    assert scan.status == ScanStatus.RUNNING
    assert scan.started_at is not None
    assert before <= scan.started_at <= after
    assert scan.finished_at is None
    assert scan.error is None


@pytest.mark.integration
def test_fr_026_running_to_done_keeps_started_and_sets_finished(db_session: Session) -> None:
    scan = _scan(db_session)
    mark_running(db_session, scan)
    started = scan.started_at

    before = datetime.now(UTC)
    mark_done(db_session, scan)
    after = datetime.now(UTC)

    assert scan.status == ScanStatus.DONE
    assert scan.started_at == started
    assert scan.finished_at is not None
    assert before <= scan.finished_at <= after
    assert scan.error is None


@pytest.mark.integration
def test_fr_026_queued_to_error_without_start(db_session: Session) -> None:
    """Сбой до начала работы: время начала пустое, завершение и причина есть."""
    scan = _scan(db_session)

    before = datetime.now(UTC)
    mark_error(db_session, scan, "  клон не удался  ")
    after = datetime.now(UTC)

    assert scan.status == ScanStatus.ERROR
    assert scan.started_at is None
    assert scan.finished_at is not None
    assert before <= scan.finished_at <= after
    assert scan.error == "клон не удался"


@pytest.mark.integration
def test_fr_026_running_to_error_keeps_started_and_sets_reason(db_session: Session) -> None:
    scan = _scan(db_session)
    mark_running(db_session, scan)
    started = scan.started_at

    mark_error(db_session, scan, "сканер упал")

    assert scan.status == ScanStatus.ERROR
    assert scan.started_at == started
    assert scan.finished_at is not None
    assert scan.error == "сканер упал"


# --- Недопустимые переходы -------------------------------------------------------


@pytest.mark.integration
@pytest.mark.parametrize(("current", "target"), INVALID_TRANSITIONS)
def test_fr_026_invalid_transition_is_rejected(
    db_session: Session, current: ScanStatus, target: ScanStatus
) -> None:
    """Недоступный переход не меняет ни статус, ни время, ни причину."""
    scan = _scan(db_session)
    _drive_to(db_session, scan, current)
    before = (scan.status, scan.started_at, scan.finished_at, scan.error)

    with pytest.raises(ScanTransitionError) as excinfo:
        _apply(db_session, scan, target)

    assert excinfo.value.scan_id == scan.id
    assert excinfo.value.current == current
    assert excinfo.value.target == target
    assert (scan.status, scan.started_at, scan.finished_at, scan.error) == before


@pytest.mark.integration
@pytest.mark.parametrize("reason", ["", "   ", "\n\t "])
def test_fr_026_error_requires_reason(db_session: Session, reason: str) -> None:
    """Пустая причина не переводит прогон в `error`."""
    scan = _scan(db_session)
    mark_running(db_session, scan)

    with pytest.raises(ValueError, match="причину"):
        mark_error(db_session, scan, reason)

    assert scan.status == ScanStatus.RUNNING
    assert scan.finished_at is None
    assert scan.error is None


@pytest.mark.integration
def test_fr_026_reason_is_rejected_for_non_error(db_session: Session) -> None:
    scan = _scan(db_session)

    with pytest.raises(ValueError, match="только для статуса error"):
        transition(db_session, scan, ScanStatus.RUNNING, reason="лишняя причина")

    assert scan.status == ScanStatus.QUEUED
    assert scan.started_at is None


# --- Задача воркера --------------------------------------------------------------


@pytest.mark.integration
def test_fr_026_process_scan_starts_queued_run(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    scan = _scan(db_session)

    before = datetime.now(UTC)
    with caplog.at_level(logging.INFO, logger=QUEUE_LOGGER):
        process_scan(str(scan.id), lambda: nullcontext(db_session))
    after = datetime.now(UTC)

    assert scan.status == ScanStatus.RUNNING
    assert scan.started_at is not None
    assert before <= scan.started_at <= after
    assert any(
        record.message == "прогон принят воркером" and record.scan_id == str(scan.id)
        for record in caplog.records
    )


@pytest.mark.integration
def test_fr_026_process_scan_keeps_time_on_repeat(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    """Повторная доставка задачи не перезаписывает время начала."""
    scan = _scan(db_session)
    process_scan(str(scan.id), lambda: nullcontext(db_session))
    started = scan.started_at

    with caplog.at_level(logging.WARNING, logger=QUEUE_LOGGER):
        process_scan(str(scan.id), lambda: nullcontext(db_session))

    assert scan.status == ScanStatus.RUNNING
    assert scan.started_at == started
    assert any("не изменён" in record.message for record in caplog.records)


@pytest.mark.integration
def test_fr_026_process_scan_ignores_unknown_run(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger=QUEUE_LOGGER):
        process_scan(str(uuid.uuid4()), lambda: nullcontext(db_session))

    assert any(record.message == "прогон не найден" for record in caplog.records)


def test_fr_026_process_scan_rejects_malformed_id(caplog: pytest.LogCaptureFixture) -> None:
    """Неверный идентификатор не открывает сессию: задача только пишет ошибку."""
    with caplog.at_level(logging.ERROR, logger=QUEUE_LOGGER):
        process_scan("not-a-uuid", _unused_scope)

    assert caplog.records[-1].scan_id == "not-a-uuid"


def test_fr_026_terminal_statuses_have_no_exit() -> None:
    assert ALLOWED_TRANSITIONS[ScanStatus.DONE] == frozenset()
    assert ALLOWED_TRANSITIONS[ScanStatus.ERROR] == frozenset()
    assert ScanStatus.QUEUED not in ALLOWED_TRANSITIONS[ScanStatus.RUNNING]
