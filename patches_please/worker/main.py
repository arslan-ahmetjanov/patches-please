"""Точка входа процесса `worker`: обработчик очереди задач RQ.

При старте воркер завершает прогоны, оставшиеся в `running` (FR-027): после
перезапуска ни один прогон не должен зависнуть в работе. В конфигурации V1
воркер один (см. `docker-compose.yml`), поэтому все `running` на момент старта
считаются прерванными предыдущим процессом. Сбои и таймауты задач разбирает
`patches_please.scans.queue.handle_scan_failure`.
"""

import logging
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Final

from redis import Redis
from rq import Queue, Worker
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.db import SessionLocal

# Регистрация таблицы projects: без неё SQLAlchemy не разрешает внешний ключ
# scans.project_id, когда воркер работает без импорта API-приложения.
import patches_please.projects.models  # noqa: F401  # isort: skip
from patches_please.scans.models import Scan
from patches_please.scans.service import ScanStatus, ScanTransitionError, mark_error

QUEUE_NAME = "patches-please"
DEFAULT_REDIS_URL = "redis://localhost:6379/0"
INTERRUPTED_REASON: Final = "Обработка прогона прервана перезапуском воркера"

logger = logging.getLogger(__name__)

# Воркер открывает сессию сам; тесты подставляют `nullcontext` с тестовой сессией.
SessionScope = Callable[[], AbstractContextManager[Session]]


def build_worker(redis_url: str) -> Worker:
    """Создаёт воркер, подписанный на очередь Patches, Please."""
    connection = Redis.from_url(redis_url)
    return Worker([Queue(QUEUE_NAME, connection=connection)], connection=connection)


def recover_interrupted_scans(session_scope: SessionScope = SessionLocal) -> int:
    """Завершает прогоны, зависшие в `running` после перезапуска воркера.

    Вызывается один раз при старте: до `work()` этот процесс ничего не
    выполняет, поэтому любой `running` прогон остался от предыдущего запуска.
    Возвращает число восстановленных прогонов — его пишет лог.
    """
    recovered = 0
    with session_scope() as session:
        statement = select(Scan).where(Scan.status == str(ScanStatus.RUNNING))
        for scan in session.scalars(statement):
            try:
                mark_error(session, scan, INTERRUPTED_REASON)
            except ScanTransitionError as exc:
                logger.warning(
                    "статус прогона не изменён: %s", exc, extra={"scan_id": str(scan.id)}
                )
                continue
            recovered += 1
            logger.info("прогон прерван перезапуском воркера", extra={"scan_id": str(scan.id)})
    return recovered


def main() -> None:
    """Запускает воркер и работает до остановки контейнера."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    redis_url = os.environ.get("REDIS_URL", DEFAULT_REDIS_URL)
    logger.info("запуск воркера, очередь %s", QUEUE_NAME)
    recovered = recover_interrupted_scans()
    if recovered:
        logger.info("восстановлено прогонов после рестарта: %s", recovered)
    build_worker(redis_url).work()


if __name__ == "__main__":
    main()
