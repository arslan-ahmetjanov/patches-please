"""Очередь прогонов: постановка задачи и приём её воркером (T-008, T-009, FR-001).

API проверку не выполняет: оно пишет строку `scans` и ставит задачу в очередь
`security-gate`, а работу забирает процесс `worker`. Идентификатор прогона
уходит аргументом-строкой, чтобы задача пережила сериализацию в Redis.

Приём задачи переводит прогон `queued → running` (FR-026): с этого момента
`started_at` заполнен, а CI видит, что проверка началась. Клонирование,
сканеры и завершение статусом `done`/`error` — следующие задачи (T-010…T-019).
Повторная доставка задачи статус не ломает: обработчик пишет предупреждение и
оставляет прогон как есть.
"""

import logging
import os
import uuid
from collections.abc import Callable
from contextlib import AbstractContextManager
from functools import lru_cache

from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.scans.models import Scan
from app.scans.service import ScanTransitionError, mark_running
from app.worker.main import DEFAULT_REDIS_URL, QUEUE_NAME

logger = logging.getLogger(__name__)

# Воркер открывает сессию сам; тесты подставляют `nullcontext` с тестовой сессией.
SessionScope = Callable[[], AbstractContextManager[Session]]


@lru_cache(maxsize=1)
def _queue(redis_url: str) -> Queue:
    """Очередь на одном соединении: `Redis.from_url` подключается лениво."""
    return Queue(QUEUE_NAME, connection=Redis.from_url(redis_url))


def get_scan_queue() -> Queue:
    """Зависимость FastAPI: очередь прогонов.

    Тесты подменяют её через `app.dependency_overrides` объектом с методом
    `enqueue`: поднимать Redis ради проверки постановки задачи не нужно.
    """
    return _queue(os.environ.get("REDIS_URL", DEFAULT_REDIS_URL))


def enqueue_scan(queue: Queue, scan_id: uuid.UUID) -> None:
    """Ставит задачу обработки прогона в очередь Security Gate."""
    queue.enqueue(process_scan, str(scan_id))


def process_scan(scan_id: str, session_scope: SessionScope = SessionLocal) -> None:
    """Приём задачи воркером: прогон переходит `queued → running` (FR-026).

    Сессию открывает сам воркер; тесты передают область с тестовой сессией,
    чтобы не ходить в базу стенда. Неизвестный прогон и повторная доставка не
    считаются ошибкой задачи: статус уже не `queued`, менять нечего.
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
