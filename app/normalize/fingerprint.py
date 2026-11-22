"""Fingerprint находки и дедупликация внутри прогона (T-012, FR-029).

Fingerprint — sha256 от `scanner|rule_id|path|normalized_snippet`: одна и та же
проблема в одном и том же месте даёт один и тот же хеш независимо от номера
строки, форматирования фрагмента и каталога клона. На этом держатся baseline
(FR-006) и классификация `new`/`existing`/`fixed` (FR-016).
"""

import hashlib
from collections.abc import Iterable
from typing import Final

from app.normalize.model import Finding

SEPARATOR: Final = "|"


def normalize_snippet(text: str) -> str:
    """Схлопывает пробельные символы фрагмента в один пробел.

    Отступы, переводы строк и двойные пробелы меняются при форматировании кода,
    хотя сама находка та же. `str.split` без аргументов режет по любой
    последовательности пробельных символов, `" ".join` собирает обратно.
    """
    return " ".join(text.split())


def compute_fingerprint(scanner: str, rule_id: str, path: str, snippet: str) -> str:
    """Считает fingerprint находки: sha256 от четырёх полей через разделитель.

    Номер строки намеренно не участвует: правка выше по файлу не должна
    превращать существующую находку в новую. Обратная сторона — переименование
    файла даёт новую находку; это принято в плане.
    """
    parts = (scanner, rule_id, path, normalize_snippet(snippet))
    payload = SEPARATOR.join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Оставляет первое вхождение каждого fingerprint в исходном порядке.

    Один сканер может найти одно и то же правило в одном файле несколько раз —
    например, разные вызовы с одинаковым фрагментом. Для baseline и отчёта это
    одна находка, поэтому дубли схлопываются внутри прогона.
    """
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        unique.append(finding)
    return unique
