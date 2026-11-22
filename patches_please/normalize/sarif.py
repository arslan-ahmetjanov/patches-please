"""Нормализация SARIF в единую модель находки (T-012, FR-003, FR-029).

Сканеры пишут SARIF 2.1.0, но заполняют его по-разному: semgrep кладёт уровень
в `level`, trivy — в `properties.severity`, gitleaks может не указывать регион
вовсе. Нормализатор приводит всё к `Finding` с обязательными полями и считает
fingerprint, не зависящий ни от номера строки, ни от каталога клона.

`workdir` — корень клона: сканеры сообщают пути абсолютными или в виде
`file://` URI, а fingerprint должен совпадать на любой машине, поэтому путь
приводится к виду относительно корня клона в POSIX-форме.

Битый или неполный SARIF — исключение на весь файл, а не находка с пустыми
полями: молча пропущенный результат исказил бы вердикт (FR-004). Текст ошибки
не содержит содержимого JSON — там могут оказаться секреты (NFR-004).

Границы: маскирование секретов — T-021, классификация `new`/`existing`/`fixed`
и baseline — T-014, сохранение в БД и отчёты — T-014/T-020.
"""

import json
from pathlib import Path
from typing import Final

from patches_please.normalize.fingerprint import compute_fingerprint, deduplicate
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.scanners.base import ScannerRun, ScannerStatus

SCANNER_TYPES: Final[dict[str, FindingType]] = {
    "semgrep": FindingType.SAST,
    "gitleaks": FindingType.SECRETS,
    "trivy": FindingType.DEPENDENCIES,
}

# Имена severity в SARIF: trivy пишет их в properties.severity, `moderate` —
# вариант GitHub-разметки, который встречается у semgrep.
SEVERITY_BY_NAME: Final[dict[str, Severity]] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Запасной источник severity — result.level из SARIF; `none` сюда не входит и
# попадает в общее умолчание.
SEVERITY_BY_LEVEL: Final[dict[str, Severity]] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
}

FILE_URI_PREFIX: Final = "file://"
DEFAULT_SEVERITY: Final = Severity.MEDIUM
DEFAULT_LINE: Final = 1


class NormalizationError(ValueError):
    """SARIF не соответствует ожидаемой структуре: файл нельзя нормализовать."""


def normalize_run(run: ScannerRun, workdir: Path) -> list[Finding]:
    """Возвращает находки одного сканера в порядке SARIF, без дублей.

    Сканер со статусом не `ok` находок не даёт: его результат — причина в
    `ScannerRun`, а не файл SARIF. Относительный `sarif_path` разрешается от
    `workdir`; абсолютный путь и `file://` URI внутри SARIF приводятся к пути
    относительно корня клона, чтобы fingerprint не зависел от каталога клона.

    Единый результат по всем `runs` файла: дубли внутри прогона схлопываются по
    fingerprint, первое вхождение сохраняет позицию в списке.
    """
    if run.status is not ScannerStatus.OK:
        return []
    finding_type = SCANNER_TYPES.get(run.scanner)
    if finding_type is None:
        raise NormalizationError(f"Неизвестный сканер: {run.scanner}")
    document = _load_document(_sarif_path(run, workdir))
    findings = [
        _build_finding(result, run.scanner, finding_type, workdir) for result in _results(document)
    ]
    return deduplicate(findings)


def _sarif_path(run: ScannerRun, workdir: Path) -> Path:
    """Путь к SARIF: относительный разрешается от корня клона."""
    if run.sarif_path is None:
        raise NormalizationError(f"Успешный запуск {run.scanner} не указывает файл SARIF")
    if run.sarif_path.is_absolute():
        return run.sarif_path
    return workdir / run.sarif_path


def _load_document(path: Path) -> dict[str, object]:
    """Читает SARIF как объект JSON; любая проблема чтения — ошибка файла."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise NormalizationError(f"Файл SARIF недоступен: {path.name}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NormalizationError(f"Файл SARIF не является JSON: {path.name}") from exc
    if not isinstance(document, dict):
        raise NormalizationError(f"SARIF должен быть объектом JSON: {path.name}")
    return document


def _results(document: dict[str, object]) -> list[dict[str, object]]:
    """Собирает results всех runs; отсутствие структуры — ошибка файла.

    Поле `results` в SARIF необязательно: отсутствие ключа и пустой список —
    валидный прогон без находок, сканер отработал и ничего не нашёл. Ошибка —
    только `results`, который не является списком.
    """
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise NormalizationError("SARIF не содержит runs")
    results: list[dict[str, object]] = []
    for entry in runs:
        if not isinstance(entry, dict):
            raise NormalizationError("Элемент runs не является объектом")
        run_results = entry.get("results", [])
        if not isinstance(run_results, list):
            raise NormalizationError("Поле results в SARIF не является списком")
        for result in run_results:
            if not isinstance(result, dict):
                raise NormalizationError("Элемент results не является объектом")
            results.append(result)
    return results


def _build_finding(
    result: dict[str, object], scanner: str, finding_type: FindingType, workdir: Path
) -> Finding:
    """Собирает находку из одного result и считает её fingerprint."""
    rule_id = _rule_id(result)
    message_text = _message_text(result)
    path, line, snippet_text = _location(result, workdir)
    message = message_text or snippet_text or rule_id
    snippet = snippet_text or message_text or rule_id
    return Finding(
        scanner=scanner,
        rule_id=rule_id,
        severity=_severity(result),
        path=path,
        line=line,
        message=message,
        finding_type=finding_type,
        fingerprint=compute_fingerprint(scanner, rule_id, path, snippet),
    )


def _rule_id(result: dict[str, object]) -> str:
    """Идентификатор правила: SARIF без ruleId нормализовать нельзя."""
    rule_id = result.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        raise NormalizationError("Результат SARIF не содержит ruleId")
    return rule_id


def _message_text(result: dict[str, object]) -> str:
    """Текст сообщения результата; пустая строка, если его нет."""
    message = result.get("message")
    if isinstance(message, dict):
        text = message.get("text")
        if isinstance(text, str):
            return text.strip()
    return ""


def _severity(result: dict[str, object]) -> Severity:
    """Единая severity: properties.severity важнее level, неизвестное — medium."""
    properties = result.get("properties")
    if isinstance(properties, dict):
        name = properties.get("severity")
        if isinstance(name, str):
            severity = SEVERITY_BY_NAME.get(name.strip().lower())
            if severity is not None:
                return severity
    level = result.get("level")
    if isinstance(level, str):
        severity = SEVERITY_BY_LEVEL.get(level.strip().lower())
        if severity is not None:
            return severity
    return DEFAULT_SEVERITY


def _location(result: dict[str, object], workdir: Path) -> tuple[str, int, str]:
    """Путь относительно клона, номер строки и фрагмент кода из location.

    Без `region.startLine` строка считается первой: gitleaks регион не пишет.
    Фрагмент берётся из `region.snippet.text`; если его нет, вызывающий код
    подставит сообщение, а затем правило (FR-029).
    """
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        raise NormalizationError("Результат SARIF не содержит locations")
    location = locations[0]
    if not isinstance(location, dict):
        raise NormalizationError("Элемент locations не является объектом")
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        raise NormalizationError("Результат SARIF не содержит physicalLocation")
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        raise NormalizationError("Результат SARIF не содержит artifactLocation")
    uri = artifact.get("uri")
    if not isinstance(uri, str) or not uri:
        raise NormalizationError("Результат SARIF не содержит uri")

    line = DEFAULT_LINE
    snippet = ""
    region = physical.get("region")
    if isinstance(region, dict):
        start_line = region.get("startLine")
        if isinstance(start_line, int) and not isinstance(start_line, bool) and start_line >= 1:
            line = start_line
        snippet = _snippet_text(region)
    return _relative_path(uri, workdir), line, snippet


def _snippet_text(region: dict[str, object]) -> str:
    """Текст фрагмента из region.snippet; пустая строка, если его нет."""
    snippet = region.get("snippet")
    if isinstance(snippet, dict):
        text = snippet.get("text")
        if isinstance(text, str):
            return text.strip()
    return ""


def _relative_path(uri: str, workdir: Path) -> str:
    """Приводит uri к пути относительно корня клона в POSIX-виде."""
    raw = uri.removeprefix(FILE_URI_PREFIX)
    if len(raw) > 2 and raw.startswith("/") and raw[2] == ":":
        # file:///C:/repo/... на Windows: слэш перед буквой диска лишний.
        raw = raw[1:]
    candidate = Path(raw)
    if candidate.is_absolute():
        try:
            candidate = candidate.resolve().relative_to(workdir.resolve())
        except ValueError as exc:
            raise NormalizationError(f"Путь находки вне корня клона: {candidate.name}") from exc
    return candidate.as_posix()
