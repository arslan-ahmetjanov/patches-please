"""Жизненный цикл прогона: допустимые переходы статусов (T-009, FR-026).

Статусы и переходы:

    queued → running → done
    queued → error
    running → error

`done` и `error` терминальны. Смена статуса проверяется здесь, а не в схеме БД:
набор статусов может вырасти, а вызывающему нужен внятный отказ, а не нарушение
ограничения на уровне базы.

Время пишется один раз: `started_at` при переходе в `running`, `finished_at`
при `done` и `error`. Причина обязательна для `error`. Функции коммитят
изменения сами — как в `app/tokens/service.py`.

`ScanStatus` объявлен здесь, потому что он нужен и сервису, и схеме ответа API.
Роутер импортирует его отсюда: имя компонента контракта (`ScanStatus`)
не меняется.
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from sqlalchemy.orm import Session

from app.scans.models import Scan


class ScanStatus(StrEnum):
    """Статусы прогона из плана: переходы по ним вводит T-009."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


# Матрица переходов: из `done` и `error` выхода нет, повтор `running` запрещён.
ALLOWED_TRANSITIONS: Final[dict[ScanStatus, frozenset[ScanStatus]]] = {
    ScanStatus.QUEUED: frozenset({ScanStatus.RUNNING, ScanStatus.ERROR}),
    ScanStatus.RUNNING: frozenset({ScanStatus.DONE, ScanStatus.ERROR}),
    ScanStatus.DONE: frozenset(),
    ScanStatus.ERROR: frozenset(),
}


class ScanTransitionError(Exception):
    """Переход, которого нет в жизненном цикле прогона.

    Несёт идентификатор и оба статуса: воркер пишет их в лог, не разбирая текст
    сообщения. Сама строка прогона при отказе не меняется.
    """

    def __init__(self, scan_id: uuid.UUID, current: str, target: str) -> None:
        self.scan_id = scan_id
        self.current = current
        self.target = target
        super().__init__(f"Недопустимый переход прогона {scan_id}: {current} → {target}")


def transition(
    session: Session,
    scan: Scan,
    target: ScanStatus,
    *,
    reason: str | None = None,
) -> Scan:
    """Переводит прогон в целевой статус или отклоняет переход.

    `reason` обязателен и непуст для `error`; для остальных статусов причина
    не принимается. Время начала и завершения заполняется только один раз.
    """
    current = ScanStatus(scan.status)
    if target not in ALLOWED_TRANSITIONS[current]:
        raise ScanTransitionError(scan.id, current, target)
    moment = datetime.now(UTC)
    if target is ScanStatus.ERROR:
        if reason is None or not reason.strip():
            raise ValueError("Статус error требует непустую причину")
        scan.error = reason.strip()
    elif reason is not None:
        raise ValueError("Причина указывается только для статуса error")
    scan.status = str(target)
    if target is ScanStatus.RUNNING and scan.started_at is None:
        scan.started_at = moment
    if target in (ScanStatus.DONE, ScanStatus.ERROR) and scan.finished_at is None:
        scan.finished_at = moment
    session.commit()
    return scan


def mark_running(session: Session, scan: Scan) -> Scan:
    """Прогон взят в работу: `queued → running`."""
    return transition(session, scan, ScanStatus.RUNNING)


def mark_done(session: Session, scan: Scan) -> Scan:
    """Прогон завершён успешно: `running → done`."""
    return transition(session, scan, ScanStatus.DONE)


def mark_error(session: Session, scan: Scan, reason: str) -> Scan:
    """Прогон завершён ошибкой: `queued`/`running` → `error` с причиной."""
    return transition(session, scan, ScanStatus.ERROR, reason=reason)
