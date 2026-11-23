"""Сохранение и чтение находок прогона (T-014, FR-003, FR-016).

Запись идемпотентна: строки прогона заменяются целиком, поэтому повторная
обработка того же прогона не плодит дубли и не требует сравнивать состояния.
Метка `new`/`existing` хранится в `findings.state` и не пересчитывается при
чтении (delta-009); `fixed` в таблицу не попадает — этих находок в прогоне нет.

`save_findings` фиксирует изменения сама, `load_findings` только читает.
"""

import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.classify import ClassificationResult
from patches_please.scans.models import FindingRecord, Scan


def save_findings(
    session: Session,
    scan: Scan,
    result: ClassificationResult,
) -> list[FindingRecord]:
    """Заменяет находки прогона результатом классификации.

    Сначала удаляются прежние строки прогона, затем вставляются новые: пара
    `(scan_id, fingerprint)` уникальна, поэтому «вставить поверх» нельзя.
    """
    session.execute(delete(FindingRecord).where(FindingRecord.scan_id == scan.id))
    records = [
        FindingRecord(
            scan_id=scan.id,
            fingerprint=item.finding.fingerprint,
            scanner=item.finding.scanner,
            rule_id=item.finding.rule_id,
            finding_type=str(item.finding.finding_type),
            severity=str(item.finding.severity),
            path=item.finding.path,
            line=item.finding.line,
            message=item.finding.message,
            state=str(item.state),
            excluded=False,
        )
        for item in result.findings
    ]
    session.add_all(records)
    session.commit()
    return records


def load_findings(session: Session, scan_id: uuid.UUID) -> list[Finding]:
    """Восстанавливает доменные находки прогона в воспроизводимом порядке.

    Сортировка по времени записи и идентификатору: набор строк у одного прогона
    неизменен, поэтому повторное чтение даёт тот же порядок.
    """
    statement = (
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan_id)
        .order_by(FindingRecord.created_at, FindingRecord.id)
    )
    return [
        Finding(
            scanner=record.scanner,
            rule_id=record.rule_id,
            severity=Severity(record.severity),
            path=record.path,
            line=record.line,
            message=record.message,
            finding_type=FindingType(record.finding_type),
            fingerprint=record.fingerprint,
        )
        for record in session.scalars(statement)
    ]


def load_records(session: Session, scan_id: uuid.UUID) -> list[FindingRecord]:
    """Строки находок прогона с метками `state` и `excluded` как в базе.

    Нужны отчёту (T-020): доменная модель `Finding` метку классификации и
    признак исключения не несёт, а порядок строк тот же, что у `load_findings`.
    """
    statement = (
        select(FindingRecord)
        .where(FindingRecord.scan_id == scan_id)
        .order_by(FindingRecord.created_at, FindingRecord.id)
    )
    return list(session.scalars(statement))
