"""Классификация находок прогона относительно базы (T-014, FR-016, FR-038).

Каждая находка получает метку `new` или `existing` по membership в fingerprints
базы. Исправленная находка в текущем прогоне отсутствует, поэтому `fixed` — это
fingerprints базы, которых в прогоне нет: отдельный отсортированный список, а не
строка `findings` (delta-009).

Порядок и дедупликация внутри прогона не меняются: дубли схлопываются до первого
вхождения (FR-029), метки проставляются в этом же порядке. Сортировка `fixed`
лексикографическая: у множества нет собственного порядка, а отчёт должен быть
воспроизводимым.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from patches_please.normalize.fingerprint import deduplicate
from patches_please.normalize.model import Finding


class FindingState(StrEnum):
    """Метка находки относительно базы сравнения (FR-016)."""

    NEW = "new"
    EXISTING = "existing"
    FIXED = "fixed"


@dataclass(frozen=True, slots=True)
class ClassifiedFinding:
    """Находка вместе с её меткой."""

    finding: Finding
    state: FindingState


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    """Результат классификации: находки по порядку прогона и исправленные fingerprints."""

    findings: tuple[ClassifiedFinding, ...]
    fixed: tuple[str, ...]

    @property
    def new_count(self) -> int:
        """Сколько находок появилось впервые."""
        return sum(1 for item in self.findings if item.state is FindingState.NEW)

    @property
    def existing_count(self) -> int:
        """Сколько находок уже было в базе."""
        return sum(1 for item in self.findings if item.state is FindingState.EXISTING)

    @property
    def fixed_count(self) -> int:
        """Сколько находок базы исчезло: метрика FR-015 берёт это число."""
        return len(self.fixed)


def classify(findings: Iterable[Finding], base: Iterable[str]) -> ClassificationResult:
    """Размечает находки прогона `new`/`existing` и считает исчезнувшие (FR-038).

    База — fingerprints baseline или предыдущего прогона. Пустая база даёт все
    находки `new` и пустой список `fixed`: это штатный первый прогон проекта.
    """
    known = frozenset(base)
    unique = deduplicate(findings)
    classified = tuple(
        ClassifiedFinding(
            finding=finding,
            state=FindingState.EXISTING if finding.fingerprint in known else FindingState.NEW,
        )
        for finding in unique
    )
    current = {finding.fingerprint for finding in unique}
    fixed = tuple(sorted(known - current))
    return ClassificationResult(findings=classified, fixed=fixed)
