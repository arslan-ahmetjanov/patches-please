"""Деградация проверки и режим отказа политики (T-019, FR-013, S-004).

Сканер, который упал или не уложился в таймаут, находок не даёт — но это не
значит, что код чист. FR-013 требует пометить такую проверку как `degraded`,
записать причину и применить режим отказа проекта:

* `fail-open` — вердикт считается по оставшимся проверкам, пайплайн не
  блокируется (S-004). Находки учитываются ровно как в T-018.
* `fail-closed` — неполная проверка даёт `fail` независимо от находок: отказ
  сканера не должен маскироваться «чистым» вердиктом.

Пометка не хранится: статус запуска уже есть в `ScannerRun`, а таблицы
`scanner_runs` пока нет. `is_degraded` выводит признак из статуса, а
`degraded_checks` отдаёт сами запуски вместе с причиной (`ScannerRun.error`) —
их покажет отчёт (T-020). История проверок и таблица `scanner_runs` — отдельная
задача: здесь нет ни схемы, ни записи в базу.

Вердикт остаётся ровно `pass`/`fail` (FR-004): `degraded` — свойство проверки,
а не третье значение, иначе CLI примет его за поломку сервиса (FR-033).
`verdict_with_degradation` — точка стыковки с вердиктом: `save_verdict`
вызывает её, когда конвейер (T-038) передал результаты запусков сканеров.
"""

from collections.abc import Iterable
from typing import Final

from patches_please.policy.verdict import FailMode, ProjectPolicy, Verdict, compute_verdict
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scans.models import FindingRecord

# Неуспешные исходы запуска: проверка не дала результата (FR-013).
DEGRADED_STATUSES: Final[frozenset[ScannerStatus]] = frozenset(
    {ScannerStatus.FAILED, ScannerStatus.TIMED_OUT}
)


def is_degraded(run: ScannerRun) -> bool:
    """Сканер упал или превысил таймаут: проверка помечается `degraded` (FR-013)."""
    return run.status in DEGRADED_STATUSES


def degraded_checks(runs: Iterable[ScannerRun]) -> tuple[ScannerRun, ...]:
    """Деградировавшие запуски в порядке входа, с причиной в `error`.

    Пустой результат — все сканеры отработали. Отсутствие сканеров вовсе эта
    функция не отличает от успеха: ожидаемый набор знает оркестратор прогона
    (T-038), здесь только исходы того, что действительно запускалось.
    """
    return tuple(run for run in runs if is_degraded(run))


def verdict_with_degradation(
    records: Iterable[FindingRecord],
    policy: ProjectPolicy,
    runs: Iterable[ScannerRun],
) -> Verdict:
    """Вердикт по находкам с учётом деградации проверок (FR-013, FR-004).

    При `fail-closed` любая деградация даёт `fail`, даже если находок нет или
    они ниже порога: неполное покрытие не выдаётся за пройденную проверку.
    При `fail-open` режим отказа не влияет на вердикт, и он считается по
    оставшимся проверкам — `compute_verdict`, как в T-018. Чистая функция:
    данные не меняются.
    """
    if policy.fail_mode is FailMode.CLOSED and degraded_checks(runs):
        return Verdict.FAIL
    return compute_verdict(records, policy.block_severities)
