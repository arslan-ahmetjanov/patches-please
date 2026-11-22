"""Очередь прогонов: постановка задачи и приём её воркером (T-008, FR-001).

API проверку не выполняет: оно пишет строку `scans` и ставит задачу в очередь
`security-gate`, а работу забирает процесс `worker`. Идентификатор прогона
уходит аргументом-строкой, чтобы задача пережила сериализацию в Redis.

В T-008 задача только фиксирует приём: статус остаётся `queued`. Клонирование,
сканеры и смена статуса — следующие задачи (T-009…T-013), и до них прогон
честно висит в очереди, а не притворяется выполненным.
"""

import logging
import os
import uuid
from functools import lru_cache

from redis import Redis
from rq import Queue

from app.worker.main import DEFAULT_REDIS_URL, QUEUE_NAME

logger = logging.getLogger(__name__)


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


def process_scan(scan_id: str) -> None:
    """Приём задачи воркером: в T-008 только запись в лог, статус не меняется."""
    logger.info("прогон принят воркером", extra={"scan_id": scan_id})
