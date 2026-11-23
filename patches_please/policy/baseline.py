"""База сравнения прогона: установка baseline и её выбор (T-014, FR-038).

Порядок выбора базы из delta-009: установленный baseline проекта → последний
завершённый (`done`) прогон проекта, кроме текущего → пустой набор. Baseline
важнее предыдущего прогона: S-003 фиксирует исторический шум проекта, после
чего сравнение идёт с зафиксированным состоянием. Пустая база — законный первый
прогон, а не ошибка: тогда все находки новые.

Baseline — снимок fingerprints выбранного прогона, а не копия находок: подробности
читаются из прогона-источника. Прогон для установки обязан быть `done`, иначе в
baseline попал бы неполный результат. Установка идемпотентна: повторный вызов
тем же прогоном не меняет ни идентификатор baseline, ни набор элементов.

`install_baseline` фиксирует изменения сама, `resolve_base` только читает.
"""

import uuid
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import delete, desc, select
from sqlalchemy.orm import Session

from patches_please.policy.models import Baseline, BaselineItem
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus


class BaselineError(ValueError):
    """Baseline нельзя установить по этому прогону."""


class BaselineSource(StrEnum):
    """Откуда взята база сравнения текущего прогона."""

    BASELINE = "baseline"
    PREVIOUS_SCAN = "previous_scan"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class BaselineSnapshot:
    """База сравнения: источник, прогон-источник и набор fingerprints."""

    source: BaselineSource
    scan_id: uuid.UUID | None
    fingerprints: frozenset[str]


def install_baseline(session: Session, scan: Scan) -> Baseline:
    """Фиксирует находки выбранного прогона как baseline проекта (FR-006).

    Прогон обязан быть `done`: по незавершённому прогону baseline зафиксировал
    бы неполный результат. Baseline проекта один — существующая строка
    переиспользуется, `scan_id` обновляется, элементы заменяются целиком.
    Поэтому повторная установка тем же прогоном ничего не меняет.
    """
    if ScanStatus(scan.status) is not ScanStatus.DONE:
        raise BaselineError(
            f"Baseline устанавливается только по завершённому прогону, а он в статусе {scan.status}"
        )

    baseline = session.scalar(select(Baseline).where(Baseline.project_id == scan.project_id))
    if baseline is None:
        baseline = Baseline(project_id=scan.project_id, scan_id=scan.id)
        session.add(baseline)
        session.flush()
    else:
        baseline.scan_id = scan.id
        # Удаление фиксируем до вставки: иначе PostgreSQL может вставить новую
        # строку с тем же первичным ключом раньше, чем удалит старую.
        session.execute(delete(BaselineItem).where(BaselineItem.baseline_id == baseline.id))
        session.flush()

    fingerprints = session.scalars(
        select(FindingRecord.fingerprint).where(FindingRecord.scan_id == scan.id).distinct()
    ).all()
    session.add_all(
        BaselineItem(baseline_id=baseline.id, fingerprint=fingerprint)
        for fingerprint in fingerprints
    )
    session.commit()
    session.refresh(baseline)
    return baseline


def resolve_base(
    session: Session,
    project_id: uuid.UUID,
    *,
    current_scan_id: uuid.UUID | None = None,
) -> BaselineSnapshot:
    """Выбирает базу сравнения для прогона проекта (FR-038).

    Baseline проекта важнее предыдущего прогона. Пока baseline не установлен,
    базой служит последний `done`-прогон проекта, кроме текущего: по времени
    начала, затем создания, затем идентификатору. Прогон в `error` базой не
    становится — его находки неполны. Изменения не фиксируются.
    """
    baseline = session.scalar(select(Baseline).where(Baseline.project_id == project_id))
    if baseline is not None:
        return BaselineSnapshot(
            source=BaselineSource.BASELINE,
            scan_id=baseline.scan_id,
            fingerprints=_baseline_fingerprints(session, baseline.id),
        )

    statement = select(Scan).where(
        Scan.project_id == project_id,
        Scan.status == ScanStatus.DONE,
    )
    if current_scan_id is not None:
        statement = statement.where(Scan.id != current_scan_id)
    previous = session.scalar(
        statement.order_by(
            desc(Scan.started_at).nulls_last(),
            desc(Scan.created_at),
            desc(Scan.id),
        ).limit(1)
    )
    if previous is None:
        return BaselineSnapshot(
            source=BaselineSource.NONE,
            scan_id=None,
            fingerprints=frozenset(),
        )
    return BaselineSnapshot(
        source=BaselineSource.PREVIOUS_SCAN,
        scan_id=previous.id,
        fingerprints=_scan_fingerprints(session, previous.id),
    )


def _baseline_fingerprints(session: Session, baseline_id: uuid.UUID) -> frozenset[str]:
    """Fingerprints элементов baseline."""
    statement = select(BaselineItem.fingerprint).where(BaselineItem.baseline_id == baseline_id)
    return frozenset(session.scalars(statement))


def _scan_fingerprints(session: Session, scan_id: uuid.UUID) -> frozenset[str]:
    """Fingerprints находок прогона."""
    statement = select(FindingRecord.fingerprint).where(FindingRecord.scan_id == scan_id)
    return frozenset(session.scalars(statement))
