"""Единая модель находки (T-012, FR-003).

Находка — результат нормализации SARIF, и дальше с ней работают все остальные
шаги: fingerprint и дедупликация (FR-029), классификация (FR-016), отчёт
(FR-008). Шесть полей FR-003 обязательны: правило, путь, строка, severity,
сканер и тип проверки. Пустых значений нет — нормализатор либо заполняет поле,
либо отвергает файл целиком.
"""

from dataclasses import dataclass
from enum import StrEnum


class Severity(StrEnum):
    """Единая шкала важности находки для политики и отчёта (FR-014)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(StrEnum):
    """Тип проверки, который дал находку (FR-002)."""

    SAST = "sast"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"


@dataclass(frozen=True, slots=True)
class Finding:
    """Нормализованная находка одного сканера.

    Поля FR-003: `rule_id`, `path`, `line`, `severity`, `scanner`, `finding_type`.
    `message` и `fingerprint` дополняют модель: сообщение нужно отчёту, а
    fingerprint — baseline и дедупликации (FR-029). Номер строки в fingerprint
    не входит: сдвиг кода не должен давать «новую» находку.
    """

    scanner: str
    rule_id: str
    severity: Severity
    path: str
    line: int
    message: str
    finding_type: FindingType
    fingerprint: str

    def __post_init__(self) -> None:
        if not self.scanner:
            raise ValueError("Имя сканера не может быть пустым")
        if not self.rule_id:
            raise ValueError("Идентификатор правила не может быть пустым")
        if not self.path:
            raise ValueError("Путь находки не может быть пустым")
        if not self.message:
            raise ValueError("Сообщение находки не может быть пустым")
        if not self.fingerprint:
            raise ValueError("Fingerprint находки не может быть пустым")
        if self.line < 1:
            raise ValueError("Номер строки начинается с единицы")
