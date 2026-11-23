"""Очередь прогонов: постановка задачи, её приём и разбор сбоя (T-008…T-010, T-038).

API проверку не выполняет: оно пишет строку `scans` и ставит задачу в очередь
`patches-please`, а работу забирает процесс `worker`. Идентификатор прогона
уходит аргументом-строкой, чтобы задача пережила сериализацию в Redis.

Приём задачи переводит прогон `queued → running` (FR-026): с этого момента
`started_at` заполнен, а CI видит, что проверка началась. Затем тот же обработчик
запускает конвейер (T-038): клон коммита, сканеры, находки, метрики и вердикт.
Предельное время задачи — `SCAN_JOB_TIMEOUT_SEC` по NFR-002; по истечении RQ
прерывает задачу исключением `JobTimeoutException`. Сбой задачи, таймаут и
гибель воркера переводят прогон в `error` с причиной и временем завершения
(FR-027): исключение и таймаут ловит `handle_scan_failure`, а прогоны,
пережившие перезапуск воркера, завершает
`patches_please.worker.main.recover_interrupted_scans`. Повторная доставка
задачи статус не ломает: обработчик пишет предупреждение и оставляет прогон
как есть.
"""

import logging
import os
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from functools import lru_cache
from types import TracebackType
from typing import Final

from redis import Redis
from rq import Callback, Queue
from rq.job import Job
from rq.timeouts import JobTimeoutException
from sqlalchemy.orm import Session

from patches_please.db import SessionLocal
from patches_please.scans.models import Scan
from patches_please.scans.pipeline import ScanPipeline, execute_scan
from patches_please.scans.service import ScanTransitionError, mark_error, mark_running
from patches_please.worker.main import DEFAULT_REDIS_URL, QUEUE_NAME

logger = logging.getLogger(__name__)

# Воркер открывает сессию сам; тесты подставляют `nullcontext` с тестовой сессией.
SessionScope = Callable[[], AbstractContextManager[Session]]

# Предельное время прогона по NFR-002: дольше 10 минут задача не живёт.
SCAN_JOB_TIMEOUT_SEC: Final = 600
# Обработчик сбоя вызывается по пути импорта: задача уже сериализована в Redis.
FAILURE_CALLBACK: Final = "patches_please.scans.queue.handle_scan_failure"
TIMEOUT_REASON_TEMPLATE: Final = "Превышен таймаут обработки прогона ({timeout} с)"
FAILURE_REASON_TEMPLATE: Final = "Обработка прогона завершилась ошибкой: {name}"
UNKNOWN_FAILURE: Final = "неизвестное исключение"


@lru_cache(maxsize=1)
def _queue(redis_url: str) -> Queue:
    """Очередь на одном соединении: `Redis.from_url` подключается лениво."""
    return Queue(
        QUEUE_NAME,
        connection=Redis.from_url(redis_url),
        default_timeout=SCAN_JOB_TIMEOUT_SEC,
    )


def get_scan_queue() -> Queue:
    """Зависимость FastAPI: очередь прогонов.

    Тесты подменяют её через `app.dependency_overrides` объектом с методом
    `enqueue`: поднимать Redis ради проверки постановки задачи не нужно.
    """
    return _queue(os.environ.get("REDIS_URL", DEFAULT_REDIS_URL))


def enqueue_scan(queue: Queue, scan_id: uuid.UUID) -> None:
    """Ставит задачу обработки прогона в очередь Patches, Please.

    Таймаут и обработчик сбоя задаются вместе с задачей: они переживают
    сериализацию в Redis и не зависят от того, какой процесс её заберёт.
    """
    queue.enqueue(
        process_scan,
        str(scan_id),
        job_timeout=SCAN_JOB_TIMEOUT_SEC,
        on_failure=Callback(FAILURE_CALLBACK),
    )


def process_scan(
    scan_id: str,
    session_scope: SessionScope = SessionLocal,
    pipeline: ScanPipeline | None = None,
) -> None:
    """Приём задачи воркером: `queued → running`, затем конвейер прогона (FR-026, T-038).

    Сессию открывает сам воркер; тесты передают область с тестовой сессией,
    чтобы не ходить в базу стенда. `pipeline` — точка подмены: по умолчанию
    запускается боевой конвейер, тесты статусов передают заглушку, чтобы не
    клонировать репозиторий и не запускать сканеры. Неизвестный прогон и
    повторная доставка не считаются ошибкой задачи: статус уже не `queued`,
    менять нечего.
    """
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        logger.error("некорректный идентификатор прогона", extra={"scan_id": scan_id})
        return
    with session_scope() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            logger.warning("прогон не найден", extra={"scan_id": scan_id})
            return
        try:
            mark_running(session, scan)
        except ScanTransitionError as exc:
            logger.warning("статус прогона не изменён: %s", exc, extra={"scan_id": scan_id})
            return
    logger.info("прогон принят воркером", extra={"scan_id": scan_id})
    handler = pipeline if pipeline is not None else execute_scan
    handler(scan_id, session_scope=session_scope)


def _job_scan_id(job: Job) -> str | None:
    """Идентификатор прогона из первого аргумента задачи."""
    args = job.args
    if not args or not isinstance(args[0], str):
        return None
    return args[0]


def _failure_reason(job: Job, exc_type: type[BaseException] | None) -> str:
    """Причина ошибки без текста исключения: в нём могут оказаться секреты."""
    if exc_type is not None and issubclass(exc_type, JobTimeoutException):
        timeout = job.timeout
        if not isinstance(timeout, int) or timeout <= 0:
            timeout = SCAN_JOB_TIMEOUT_SEC
        return TIMEOUT_REASON_TEMPLATE.format(timeout=timeout)
    name = exc_type.__name__ if exc_type is not None else UNKNOWN_FAILURE
    return FAILURE_REASON_TEMPLATE.format(name=name)


def handle_scan_failure(
    job: Job,
    connection: Redis | None,
    exc_type: type[BaseException] | None,
    exc_value: BaseException | None,
    traceback: TracebackType | None,
    session_scope: SessionScope = SessionLocal,
) -> None:
    """Обработчик сбоя задачи: прогон переходит в `error` (FR-027).

    RQ вызывает его при исключении задачи, при таймауте и при зачистке
    брошенной задачи. Текст исключения в причину не попадает: только тип.
    Повторный вызов на терминальном прогоне ничего не меняет — зачистка RQ
    может сработать уже после перезапуска воркера.
    """
    scan_id = _job_scan_id(job)
    if scan_id is None:
        logger.error("задача без идентификатора прогона", extra={"job_id": job.id})
        return
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        logger.error("некорректный идентификатор прогона", extra={"scan_id": scan_id})
        return
    with session_scope() as session:
        scan = session.get(Scan, scan_uuid)
        if scan is None:
            logger.warning("прогон не найден", extra={"scan_id": scan_id})
            return
        try:
            mark_error(session, scan, _failure_reason(job, exc_type))
        except ScanTransitionError as exc:
            logger.warning("статус прогона не изменён: %s", exc, extra={"scan_id": scan_id})
            return
    logger.info("прогон завершён ошибкой после сбоя задачи", extra={"scan_id": scan_id})
