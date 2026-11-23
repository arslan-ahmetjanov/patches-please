"""Пороги политики и вердикт прогона (T-017, FR-004, FR-014).

Политика проекта задаёт уровни severity, при которых новая находка делает
вердикт `fail`. Пороги настраиваются отдельно для каждого проекта (FR-014),
поэтому политика читается по `project_id` прогона. Пока строки `policies` нет,
действует умолчание: блокируются `critical` и `high` — предусловие S-002.

Вердикт считается только по находкам `state=new` с `excluded=false`: находки
из baseline не блокируют (FR-006, S-003), исключённые — тоже (FR-011, S-005),
но остаются в отчёте. Значений ровно два — `pass` и `fail` (FR-004).

`apply_exceptions` проставляет `findings.excluded` по действующим исключениям
проекта, `save_verdict` пишет `scans.verdict` — по образцу `save_metrics` из
`patches_please/metrics/service.py`: расчёт отдельно, запись отдельно.
Встраивание в обработку прогона — T-018/T-020, здесь только расчёт и запись.

`Verdict` объявлен в этом модуле: имя компонента контракта (`Verdict`) не
меняется, а роутер прогонов импортирует его отсюда.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.classify import FindingState
from patches_please.policy.exceptions import active_exceptions, is_excluded
from patches_please.policy.models import Policy
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus


class Verdict(StrEnum):
    """Вердикт по политике проекта (FR-004): ровно два значения."""

    PASS = "pass"
    FAIL = "fail"


class FailMode(StrEnum):
    """Поведение при деградировавшем сканере (FR-013); читает T-019."""

    OPEN = "open"
    CLOSED = "closed"


# Умолчание политики: блокировать критичное и высокое, как в предусловии S-002.
DEFAULT_BLOCK_SEVERITIES: Final[frozenset[Severity]] = frozenset({Severity.CRITICAL, Severity.HIGH})
DEFAULT_FAIL_MODE: Final = FailMode.OPEN
# Совпадает с `DEFAULT_SCANNER_TIMEOUT_SEC` из `patches_please/scanners/runner.py`.
DEFAULT_SCANNER_TIMEOUT_SEC: Final = 300


class PolicyError(ValueError):
    """Политику нельзя сохранить или применить к прогону."""


@dataclass(frozen=True, slots=True)
class ProjectPolicy:
    """Действующая политика проекта: строка `policies` или умолчание."""

    block_severities: frozenset[Severity]
    fail_mode: FailMode
    scanner_timeout_sec: int


DEFAULT_POLICY: Final = ProjectPolicy(
    block_severities=DEFAULT_BLOCK_SEVERITIES,
    fail_mode=DEFAULT_FAIL_MODE,
    scanner_timeout_sec=DEFAULT_SCANNER_TIMEOUT_SEC,
)


def load_policy(session: Session, project_id: uuid.UUID) -> ProjectPolicy:
    """Действующая политика проекта; без строки — умолчание (FR-014).

    Уровни приводятся к `Severity`: недопустимое значение в строке — ошибка
    данных, а не тихий пропуск порога. Изменения не фиксируются.
    """
    row = session.get(Policy, project_id)
    if row is None:
        return DEFAULT_POLICY
    return ProjectPolicy(
        block_severities=frozenset(Severity(value) for value in row.block_severities),
        fail_mode=FailMode(row.fail_mode),
        scanner_timeout_sec=row.scanner_timeout_sec,
    )


def upsert_policy(
    session: Session,
    project_id: uuid.UUID,
    *,
    block_severities: Iterable[Severity],
    fail_mode: FailMode = DEFAULT_FAIL_MODE,
    scanner_timeout_sec: int = DEFAULT_SCANNER_TIMEOUT_SEC,
) -> Policy:
    """Создаёт или заменяет политику проекта одной транзакцией.

    Уровни дедуплицируются и приводятся к порядку шкалы FR-014: повторный `PUT`
    с тем же набором не меняет ни значения, ни порядок. Положительный таймаут
    проверяется и здесь, хотя схема API отсекает ноль на границе.
    """
    if scanner_timeout_sec <= 0:
        raise PolicyError("Таймаут сканеров должен быть положительным")

    row = session.get(Policy, project_id)
    if row is None:
        row = Policy(project_id=project_id)
        session.add(row)
    row.block_severities = [str(severity) for severity in _ordered_severities(block_severities)]
    row.fail_mode = str(fail_mode)
    row.scanner_timeout_sec = scanner_timeout_sec
    session.commit()
    session.refresh(row)
    return row


def apply_exceptions(
    session: Session,
    scan: Scan,
    *,
    now: datetime | None = None,
) -> int:
    """Проставляет `findings.excluded` по действующим исключениям проекта.

    Возвращает число исключённых находок. Момент фиксируется один раз на прогон:
    иначе исключение, истекающее между строками, дало бы разный ответ для
    одинаковых находок. Изменения фиксируются.
    """
    moment = now or datetime.now(UTC)
    exceptions = active_exceptions(session, scan.project_id, now=moment)
    records = _scan_findings(session, scan)
    excluded = 0
    for record in records:
        record.excluded = is_excluded(_finding(record), exceptions, moment)
        if record.excluded:
            excluded += 1
    session.commit()
    return excluded


def compute_verdict(
    records: Iterable[FindingRecord],
    block_severities: Iterable[Severity],
) -> Verdict:
    """Вердикт по находкам прогона: `fail` при новой неисключённой находке.

    Блокирующими считаются уровни из политики проекта (FR-014). Находки
    `existing` (база сравнения) и `excluded` (действующее исключение) вердикт
    не меняют (FR-006, FR-011). Чистая функция: данные не меняются.
    """
    blocking = {str(severity) for severity in block_severities}
    for record in records:
        if record.state == FindingState.NEW and not record.excluded and record.severity in blocking:
            return Verdict.FAIL
    return Verdict.PASS


def save_verdict(session: Session, scan: Scan) -> Verdict:
    """Считает вердикт прогона по политике проекта и пишет его в `scans.verdict`.

    Прогон обязан быть `done`: по незавершённому набор находок неполон, как
    и у метрик (T-016). Повторный вызов даёт тот же вердикт: пороги и находки
    к этому моменту не меняются. Изменения фиксируются.
    """
    if ScanStatus(scan.status) is not ScanStatus.DONE:
        raise PolicyError(
            f"Вердикт выносится только по завершённому прогону, а он в статусе {scan.status}"
        )
    policy = load_policy(session, scan.project_id)
    verdict = compute_verdict(_scan_findings(session, scan), policy.block_severities)
    scan.verdict = str(verdict)
    session.commit()
    return verdict


def _ordered_severities(values: Iterable[Severity]) -> tuple[Severity, ...]:
    """Уникальные уровни в порядке шкалы FR-014: запись и ответ воспроизводимы."""
    present = frozenset(values)
    return tuple(severity for severity in Severity if severity in present)


def _scan_findings(session: Session, scan: Scan) -> list[FindingRecord]:
    """Находки прогона в воспроизводимом порядке: как в `load_findings`."""
    statement = (
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan.id)
        .order_by(FindingRecord.created_at, FindingRecord.id)
    )
    return list(session.scalars(statement))


def _finding(record: FindingRecord) -> Finding:
    """Доменная находка из строки: предикат исключения принимает `Finding`."""
    return Finding(
        scanner=record.scanner,
        rule_id=record.rule_id,
        severity=Severity(record.severity),
        path=record.path,
        line=record.line,
        message=record.message,
        finding_type=FindingType(record.finding_type),
        fingerprint=record.fingerprint,
    )
