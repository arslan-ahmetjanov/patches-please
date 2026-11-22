"""Устойчивость воркера: сбой, таймаут и рестарт задачи (T-010, FR-027).

Проверяется разбор сбоя задачи и разовая зачистка при старте воркера.
Обработчик сбоя вызывается напрямую с тестовой сессией — так же, как его
вызовет RQ; реальный воркер и Redis для этих проверок не нужны.
"""

import logging
import subprocess
import sys
import uuid
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rq import Callback
from rq.timeouts import JobTimeoutException
from sqlalchemy.orm import Session

from app.projects.models import Project
from app.scans.models import Scan
from app.scans.queue import (
    FAILURE_CALLBACK,
    SCAN_JOB_TIMEOUT_SEC,
    enqueue_scan,
    handle_scan_failure,
    process_scan,
)
from app.scans.service import ScanStatus, mark_done, mark_running
from app.worker.main import INTERRUPTED_REASON, recover_interrupted_scans

SHA = "b" * 40
QUEUE_LOGGER = "app.scans.queue"
WORKER_LOGGER = "app.worker.main"
ROOT = Path(__file__).resolve().parent.parent


class FakeJob:
    """Минимум полей задачи RQ, которые читает обработчик сбоя."""

    def __init__(self, scan_id: object, timeout: int | None = SCAN_JOB_TIMEOUT_SEC) -> None:
        self.id = f"job-{uuid.uuid4().hex[:8]}"
        self.args = (scan_id,)
        self.timeout = timeout


class RecordingQueue:
    """Очередь, которая запоминает задачу и её параметры, не ходя в Redis."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, str, dict[str, object]]] = []

    def enqueue(self, func: object, scan_id: str, **options: object) -> None:
        self.calls.append((func, scan_id, options))


def _scan(session: Session) -> Scan:
    """Прогон в статусе `queued`: проект нужен только ради внешнего ключа."""
    project = Project(name="Демо", slug=f"worker-{uuid.uuid4().hex[:8]}")
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


def _running_scan(session: Session) -> Scan:
    scan = _scan(session)
    mark_running(session, scan)
    return scan


def _unused_scope() -> AbstractContextManager[Session]:
    """Область сессии, которая не должна открываться: тест ловит лишний запрос."""
    raise AssertionError("сессия не должна открываться")


# --- Сбой задачи -----------------------------------------------------------------


@pytest.mark.integration
def test_fr_027_exception_marks_scan_error(db_session: Session) -> None:
    """Исключение задачи переводит `running` в `error` с причиной и временем."""
    scan = _running_scan(db_session)
    started = scan.started_at
    job = FakeJob(str(scan.id))

    before = datetime.now(UTC)
    handle_scan_failure(
        job,
        None,
        RuntimeError,
        RuntimeError("секрет из репозитория"),
        None,
        lambda: nullcontext(db_session),
    )
    after = datetime.now(UTC)

    assert scan.status == ScanStatus.ERROR
    assert scan.started_at == started
    assert scan.finished_at is not None
    assert before <= scan.finished_at <= after
    assert scan.error is not None
    assert "RuntimeError" in scan.error
    # Текст исключения может содержать данные репозитория, в причину он не попадает.
    assert "секрет" not in scan.error


@pytest.mark.integration
def test_fr_027_timeout_marks_scan_error(db_session: Session) -> None:
    """Таймаут задачи даёт причину с предельным временем прогона."""
    scan = _running_scan(db_session)

    handle_scan_failure(
        FakeJob(str(scan.id)),
        None,
        JobTimeoutException,
        JobTimeoutException(),
        None,
        lambda: nullcontext(db_session),
    )

    assert scan.status == ScanStatus.ERROR
    assert scan.finished_at is not None
    assert scan.error is not None
    assert "таймаут" in scan.error.lower()
    assert str(SCAN_JOB_TIMEOUT_SEC) in scan.error


@pytest.mark.integration
def test_fr_027_failure_before_start_fills_only_finished_at(db_session: Session) -> None:
    """Сбой до перехода в `running` не выдумывает время начала."""
    scan = _scan(db_session)

    handle_scan_failure(
        FakeJob(str(scan.id)),
        None,
        ValueError,
        ValueError("плохие данные"),
        None,
        lambda: nullcontext(db_session),
    )

    assert scan.status == ScanStatus.ERROR
    assert scan.started_at is None
    assert scan.finished_at is not None
    assert scan.error is not None


@pytest.mark.integration
def test_fr_027_failure_keeps_terminal_scan(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    """Повторный вызов на завершённом прогоне ничего не меняет."""
    scan = _running_scan(db_session)
    mark_done(db_session, scan)
    finished = scan.finished_at

    with caplog.at_level(logging.WARNING, logger=QUEUE_LOGGER):
        handle_scan_failure(
            FakeJob(str(scan.id)),
            None,
            RuntimeError,
            RuntimeError("поздний сбой"),
            None,
            lambda: nullcontext(db_session),
        )

    assert scan.status == ScanStatus.DONE
    assert scan.finished_at == finished
    assert scan.error is None
    assert any("не изменён" in record.message for record in caplog.records)


@pytest.mark.integration
def test_fr_027_failure_ignores_unknown_scan(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    job = FakeJob(str(uuid.uuid4()))

    with caplog.at_level(logging.WARNING, logger=QUEUE_LOGGER):
        handle_scan_failure(
            job,
            None,
            RuntimeError,
            RuntimeError("сбой"),
            None,
            lambda: nullcontext(db_session),
        )

    assert any(record.message == "прогон не найден" for record in caplog.records)


def test_fr_027_failure_ignores_malformed_id(caplog: pytest.LogCaptureFixture) -> None:
    """Неверный идентификатор не открывает сессию: задача только пишет ошибку."""
    with caplog.at_level(logging.ERROR, logger=QUEUE_LOGGER):
        handle_scan_failure(
            FakeJob("not-a-uuid"),
            None,
            RuntimeError,
            RuntimeError("сбой"),
            None,
            _unused_scope,
        )

    assert caplog.records[-1].scan_id == "not-a-uuid"


def test_fr_027_failure_ignores_job_without_arguments(
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = FakeJob(None)
    job.args = ()

    with caplog.at_level(logging.ERROR, logger=QUEUE_LOGGER):
        handle_scan_failure(job, None, RuntimeError, RuntimeError("сбой"), None, _unused_scope)

    assert any(record.message == "задача без идентификатора прогона" for record in caplog.records)


# --- Рестарт воркера -------------------------------------------------------------


@pytest.mark.integration
def test_fr_027_recovery_errors_interrupted_runs(db_session: Session) -> None:
    """При старте `running` становится `error`, остальные статусы не трогаются."""
    queued = _scan(db_session)
    running = _running_scan(db_session)
    started = running.started_at
    done = _running_scan(db_session)
    mark_done(db_session, done)

    before = datetime.now(UTC)
    recovered = recover_interrupted_scans(lambda: nullcontext(db_session))
    after = datetime.now(UTC)

    assert recovered == 1
    assert running.status == ScanStatus.ERROR
    assert running.started_at == started
    assert running.finished_at is not None
    assert before <= running.finished_at <= after
    assert running.error == INTERRUPTED_REASON
    assert queued.status == ScanStatus.QUEUED
    assert queued.error is None
    assert done.status == ScanStatus.DONE
    assert done.error is None


@pytest.mark.integration
def test_fr_027_recovery_is_idempotent(db_session: Session) -> None:
    """Повторный старт воркера не переписывает уже восстановленный прогон."""
    running = _running_scan(db_session)
    recover_interrupted_scans(lambda: nullcontext(db_session))
    finished = running.finished_at

    assert recover_interrupted_scans(lambda: nullcontext(db_session)) == 0
    assert running.status == ScanStatus.ERROR
    assert running.finished_at == finished
    assert running.error == INTERRUPTED_REASON


@pytest.mark.integration
def test_fr_027_recovery_logs_scan_id(
    db_session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    running = _running_scan(db_session)

    with caplog.at_level(logging.INFO, logger=WORKER_LOGGER):
        recover_interrupted_scans(lambda: nullcontext(db_session))

    assert any(
        record.message == "прогон прерван перезапуском воркера"
        and record.scan_id == str(running.id)
        for record in caplog.records
    )


# --- Параметры задачи ------------------------------------------------------------


def test_fr_027_worker_registers_project_table() -> None:
    """Воркер без импорта API-приложения разрешает внешний ключ `scans.project_id`.

    Проверка идёт в отдельном процессе: в тестовом процессе `app.main` уже
    импортирован и зарегистрировал все таблицы, поэтому регрессию не увидеть.
    """
    code = (
        "import app.worker.main\n"
        "from app.db import Base\n"
        "assert 'projects' in Base.metadata.tables, sorted(Base.metadata.tables)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_fr_027_enqueue_sets_timeout_and_failure_callback() -> None:
    """Таймаут и обработчик сбоя уходят вместе с задачей в Redis."""
    queue = RecordingQueue()
    scan_id = uuid.uuid4()

    enqueue_scan(queue, scan_id)

    func, passed_id, options = queue.calls[0]
    assert func is process_scan
    assert passed_id == str(scan_id)
    assert options["job_timeout"] == SCAN_JOB_TIMEOUT_SEC == 600
    callback = options["on_failure"]
    assert isinstance(callback, Callback)
    assert callback.name == FAILURE_CALLBACK
