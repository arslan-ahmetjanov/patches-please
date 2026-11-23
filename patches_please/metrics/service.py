"""Расчёт и сохранение метрик завершённого прогона (T-016, FR-015).

FR-015 требует пять величин: длительность, число находок по severity, число
новых, число исправленных и долю исключённых. Все они живут в `scans.timings`
(jsonb): отдельной таблицы под метрики нет, а история прогонов уже читается
страницей проекта и отчётом.

Источники:

- длительность — разница `started_at` и `finished_at` в секундах;
- находки по severity — строки `findings` прогона; все пять ключей шкалы FR-014
  присутствуют всегда, нули допустимы: пустой прогон — законный результат;
- `new` — метка `findings.state`, проставленная при классификации (FR-016);
- `fixed` — fingerprints базы сравнения, которых в прогоне нет; база выбирается
  в `patches_please/policy/baseline.py` так же, как для вердикта, поэтому метрика
  и классификация не расходятся;
- доля исключённых — `excluded / всего находок`; при пустом прогоне знаменателя
  нет и доля равна нулю, а не ошибке.

Метрики считаются только по прогону в статусе `done`: по незавершённому нет ни
времени завершения, ни полного набора находок. Заполнение `excluded` и сам
вердикт — T-017, поэтому доля исключённых до него всегда нулевая: флаг в базе
пока никто не поднимает.

`save_metrics` фиксирует изменения сама, `compute_metrics` и `load_metrics`
только читают.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.normalize.model import Severity
from patches_please.policy.baseline import resolve_base
from patches_please.policy.classify import FindingState
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus

# Порядок ключей повторяет шкалу FR-014: от самого тяжёлого к информационному.
SEVERITY_KEYS: Final[tuple[str, ...]] = tuple(str(severity) for severity in Severity)


class MetricsError(ValueError):
    """Метрики нельзя посчитать или прочитать: прогон или запись не годятся."""


@dataclass(frozen=True, slots=True)
class RunMetrics:
    """Пять метрик прогона из FR-015."""

    duration_sec: float
    # Все пять ключей шкалы, нули не опускаются: отчёт не должен считать пропуски.
    findings_by_severity: dict[str, int]
    new: int
    fixed: int
    excluded_ratio: float

    def as_dict(self) -> dict[str, Any]:
        """Представление для `scans.timings`: набор и вложенность ключей стабильны."""
        return {
            "duration_sec": self.duration_sec,
            "findings_by_severity": dict(self.findings_by_severity),
            "new": self.new,
            "fixed": self.fixed,
            "excluded_ratio": self.excluded_ratio,
        }


def compute_metrics(session: Session, scan: Scan) -> RunMetrics:
    """Считает пять метрик завершённого прогона (FR-015), не меняя данных.

    Прогон вне статуса `done` и прогон без времени начала или завершения
    отклоняются: длительность по ним не определена, а находки могут быть
    неполными. Изменения не фиксируются.
    """
    if ScanStatus(scan.status) is not ScanStatus.DONE:
        raise MetricsError(
            f"Метрики считаются только по завершённому прогону, а он в статусе {scan.status}"
        )
    if scan.started_at is None or scan.finished_at is None:
        raise MetricsError("У завершённого прогона нет времени начала или завершения")

    records = _scan_findings(session, scan)
    base = resolve_base(session, scan.project_id, current_scan_id=scan.id)
    current = {record.fingerprint for record in records}

    return RunMetrics(
        duration_sec=(scan.finished_at - scan.started_at).total_seconds(),
        findings_by_severity=_severity_counts(records),
        new=sum(1 for record in records if record.state == FindingState.NEW),
        fixed=len(base.fingerprints - current),
        excluded_ratio=_excluded_ratio(records),
    )


def save_metrics(session: Session, scan: Scan) -> RunMetrics:
    """Считает метрики прогона и пишет их в `scans.timings`.

    Значение записывается целиком и фиксируется сразу: повторный вызов на том же
    прогоне даёт тот же набор, потому что метрики выводятся из неизменных данных.
    """
    metrics = compute_metrics(session, scan)
    scan.timings = metrics.as_dict()
    session.commit()
    return metrics


def load_metrics(scan: Scan) -> RunMetrics:
    """Читает метрики из `scans.timings` обратно в `RunMetrics`.

    Отсутствующая или повреждённая запись — ошибка, а не нули: ноль как метрика
    и отсутствие метрики должны различаться и в отчёте, и в тестах.
    """
    stored = scan.timings
    if not stored:
        raise MetricsError(f"У прогона {scan.id} нет сохранённых метрик")
    try:
        return RunMetrics(
            duration_sec=float(stored["duration_sec"]),
            findings_by_severity={
                severity: int(stored["findings_by_severity"][severity])
                for severity in SEVERITY_KEYS
            },
            new=int(stored["new"]),
            fixed=int(stored["fixed"]),
            excluded_ratio=float(stored["excluded_ratio"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise MetricsError(f"Метрики прогона {scan.id} неполны или повреждены") from exc


def _scan_findings(session: Session, scan: Scan) -> list[FindingRecord]:
    """Находки прогона в воспроизводимом порядке: как в `load_findings`."""
    statement = (
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan.id)
        .order_by(FindingRecord.created_at, FindingRecord.id)
    )
    return list(session.scalars(statement))


def _severity_counts(records: Iterable[FindingRecord]) -> dict[str, int]:
    """Считает находки по всем пяти уровням шкалы; неизвестный уровень — отказ."""
    counts = dict.fromkeys(SEVERITY_KEYS, 0)
    for record in records:
        if record.severity not in counts:
            raise MetricsError(f"Неизвестная важность находки: {record.severity}")
        counts[record.severity] += 1
    return counts


def _excluded_ratio(records: list[FindingRecord]) -> float:
    """Доля исключённых находок; пустой прогон даёт ноль, а не деление на ноль."""
    if not records:
        return 0.0
    excluded = sum(1 for record in records if record.excluded)
    return excluded / len(records)
