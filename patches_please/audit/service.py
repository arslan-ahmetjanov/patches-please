"""Запись событий журнала аудита (T-015, S-005).

`record_event` только добавляет запись в сессию и не коммитит: действие и его
след в журнале должны попасть в базу одной транзакцией. Коммит делает
вызывающий сервис — иначе при ошибке после записи события журнал утверждал бы
о действии, которого не было.

Секретов в журнале нет по построению: `payload` собирает вызывающий из явного
списка полей. Свободный текст (например, причина исключения) сюда не
передаётся — он хранится в самой сущности.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from patches_please.audit.models import AuditEvent


def record_event(
    session: Session,
    *,
    actor: uuid.UUID | None,
    action: str,
    entity: str,
    payload: dict[str, Any] | None = None,
) -> AuditEvent:
    """Добавляет событие в текущую транзакцию и возвращает его.

    Проверяются только обязательные строки: действие и объект не могут быть
    пустыми, иначе запись в журнале невозможно отфильтровать. Коммит остаётся
    за вызывающим.
    """
    if not action.strip():
        raise ValueError("Действие аудита не может быть пустым")
    if not entity.strip():
        raise ValueError("Объект аудита не может быть пустым")
    event = AuditEvent(
        actor=actor,
        action=action.strip(),
        entity=entity.strip(),
        payload=dict(payload or {}),
    )
    session.add(event)
    return event
