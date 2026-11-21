"""Точка входа процесса `worker`: обработчик очереди задач RQ."""

import logging
import os

from redis import Redis
from rq import Queue, Worker

QUEUE_NAME = "security-gate"
DEFAULT_REDIS_URL = "redis://localhost:6379/0"

logger = logging.getLogger(__name__)


def build_worker(redis_url: str) -> Worker:
    """Создаёт воркер, подписанный на очередь Security Gate."""
    connection = Redis.from_url(redis_url)
    return Worker([Queue(QUEUE_NAME, connection=connection)], connection=connection)


def main() -> None:
    """Запускает воркер и работает до остановки контейнера."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    redis_url = os.environ.get("REDIS_URL", DEFAULT_REDIS_URL)
    logger.info("запуск воркера, очередь %s", QUEUE_NAME)
    build_worker(redis_url).work()


if __name__ == "__main__":
    main()
