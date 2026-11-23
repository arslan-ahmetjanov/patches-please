"""Исключения находок: причина, срок и автоповтор после истечения (T-015).

Исключение привязано к проекту и правилу: `rule_id` сравнивается точно,
`path_glob` ограничивает пути, `expires_at` задаёт срок, `revoked_at` закрывает
исключение досрочно. Пока исключение активно, находка не влияет на вердикт
(FR-011); после срока или отзыва она снова учитывается (FR-012, S-005).

Пути сопоставляются `fnmatch.fnmatchcase` по строке как есть: путь находки —
POSIX-подобный, из SARIF; `*` совпадает и с `/`, поэтому `src/*.py` накрывает и
вложенные каталоги. Отдельного синтаксиса `**` нет — поведение зафиксировано в
docstring и тестах, чтобы интерфейс и проверка не разошлись.

Создание и отзыв пишут событие в журнал аудита в той же транзакции, что и само
изменение: записи о действии без действия не бывает. В `payload` попадают
только явные поля, свободный текст причины туда не копируется — он хранится в
самой строке исключения.

Границы: вердикт и пороги — T-017, формы и маршруты (включая чтение текущего
пользователя) — T-024, маскирование секретов — T-021. Здесь только хранение
и предикат исключения.
"""

import fnmatch
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.audit.service import record_event
from patches_please.normalize.model import Finding
from patches_please.policy.models import ExceptionRecord

# Действия журнала: значения стабильны, по ним фильтруется история.
AUDIT_EXCEPTION_CREATED: Final = "exception.created"
AUDIT_EXCEPTION_REVOKED: Final = "exception.revoked"


class ExceptionValidationError(ValueError):
    """Исключение создаётся или отзывается с недопустимыми данными."""


class ExceptionNotFoundError(LookupError):
    """Исключение с таким идентификатором не найдено."""


def _required_text(value: str | None, label: str) -> str:
    """Возвращает непустую строку без краевых пробелов или отклоняет поле."""
    text = (value or "").strip()
    if not text:
        raise ExceptionValidationError(f"Поле «{label}» обязательно")
    return text


def create_exception(
    session: Session,
    *,
    project_id: uuid.UUID,
    rule_id: str,
    path_glob: str,
    reason: str,
    author_id: uuid.UUID | None,
    expires_at: datetime | None,
) -> ExceptionRecord:
    """Создаёт исключение с обязательными полями FR-011 и пишет аудит.

    Правило, путь, причина, автор и срок обязательны: пустое значение отклоняется
    с именем поля, чтобы форма T-024 могла показать его рядом с вводом. Срок
    должен быть с часовым поясом — иначе сравнение с моментом прогона зависело
    бы от часового пояса сервера. Прошедший срок не запрещён: такое исключение
    сразу неактивно, и это видно по `is_excluded`.

    Изменение фиксируется вместе с событием аудита одной транзакцией.
    """
    if author_id is None:
        raise ExceptionValidationError("Поле «автор» обязательно")
    if expires_at is None:
        raise ExceptionValidationError("Поле «срок действия» обязательно")
    if expires_at.tzinfo is None:
        raise ExceptionValidationError("Срок действия должен содержать часовой пояс")

    record = ExceptionRecord(
        project_id=project_id,
        rule_id=_required_text(rule_id, "правило"),
        path_glob=_required_text(path_glob, "путь"),
        reason=_required_text(reason, "причина"),
        author_id=author_id,
        expires_at=expires_at,
    )
    session.add(record)
    # Идентификатор нужен для entity события: генерирует его PostgreSQL.
    session.flush()
    record_event(
        session,
        actor=author_id,
        action=AUDIT_EXCEPTION_CREATED,
        entity=f"exception:{record.id}",
        payload={
            "project_id": str(record.project_id),
            "rule_id": record.rule_id,
            "path_glob": record.path_glob,
            "expires_at": record.expires_at.isoformat(),
        },
    )
    session.commit()
    return record


def revoke_exception(
    session: Session,
    exception_id: uuid.UUID,
    *,
    actor: uuid.UUID,
    now: datetime | None = None,
) -> ExceptionRecord:
    """Отзывает исключение досрочно и пишет аудит.

    Повторный отзыв отклоняется: время отзыва пишется один раз, как и время
    завершения прогона в `patches_please/scans/service.py`.
    """
    record = session.get(ExceptionRecord, exception_id)
    if record is None:
        raise ExceptionNotFoundError(f"Исключение {exception_id} не найдено")
    if record.revoked_at is not None:
        raise ExceptionValidationError("Исключение уже отозвано")

    moment = now or datetime.now(UTC)
    record.revoked_at = moment
    record_event(
        session,
        actor=actor,
        action=AUDIT_EXCEPTION_REVOKED,
        entity=f"exception:{record.id}",
        payload={
            "project_id": str(record.project_id),
            "revoked_at": moment.isoformat(),
        },
    )
    session.commit()
    return record


def active_exceptions(
    session: Session,
    project_id: uuid.UUID,
    *,
    now: datetime,
) -> list[ExceptionRecord]:
    """Исключения проекта, действующие на момент прогона `now`.

    Отозванные и истёкшие не возвращаются: после срока находка снова учитывается
    (FR-012). Поле `expires_at` считается закрытым в сам момент истечения —
    активность строгая (`now < expires_at`).
    """
    statement = (
        select(ExceptionRecord)
        .where(
            ExceptionRecord.project_id == project_id,
            ExceptionRecord.revoked_at.is_(None),
            ExceptionRecord.expires_at > now,
        )
        .order_by(ExceptionRecord.created_at, ExceptionRecord.id)
    )
    return list(session.scalars(statement))


def is_excluded(
    finding: Finding,
    exceptions: Iterable[ExceptionRecord],
    now: datetime,
) -> bool:
    """Учитывает ли находку действующее исключение на момент `now` (FR-011, FR-012).

    Совпадать должны правило и путь; исключение должно быть не отозвано и не
    истекло. Список исключений передаётся уже отобранным по проекту находки:
    проект в находке не хранится, а смешивать исключения разных проектов нельзя.
    """
    return any(
        exception.rule_id == finding.rule_id
        and fnmatch.fnmatchcase(finding.path, exception.path_glob)
        and exception.revoked_at is None
        and exception.expires_at > now
        for exception in exceptions
    )
