"""Нормализация SARIF, fingerprint и дедупликация (T-012, FR-003, FR-029).

Тесты работают на фикстурах `tests/fixtures`: вымышленные SARIF трёх сканеров с
теми же различиями, что у настоящих инструментов — уровень в `level` или
`properties.severity`, отсутствие региона у gitleaks, повтор одного правила в
одном файле. Реальные сканеры, сеть и бинарники не нужны.
"""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from patches_please.normalize.fingerprint import compute_fingerprint, deduplicate, normalize_snippet
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.normalize.sarif import NormalizationError, normalize_run
from patches_please.scanners.base import ScannerRun, ScannerStatus

FIXTURES = Path(__file__).parent / "fixtures"


def _run(scanner: str, sarif_path: Path) -> ScannerRun:
    """Успешный запуск сканера: нормализации нужен только путь к SARIF."""
    return ScannerRun(
        scanner=scanner,
        status=ScannerStatus.OK,
        duration_ms=0,
        sarif_path=sarif_path,
    )


def _fixture_run(scanner: str, filename: str) -> ScannerRun:
    """Запуск сканера на фикстуре из `tests/fixtures`."""
    return _run(scanner, FIXTURES / filename)


def _result(uri: str = "src/app.py", rule_id: str = "rule") -> dict[str, object]:
    """Результат SARIF с одним location; отдельные поля меняются в тестах."""
    return {
        "ruleId": rule_id,
        "message": {"text": "сообщение"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }


def _write_sarif(path: Path, result: dict[str, object]) -> Path:
    """Пишет минимальный SARIF с одним результатом во временный файл."""
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [result]}],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _finding(*, fingerprint: str, line: int = 1) -> Finding:
    """Находка для проверки дедупликации без файла SARIF."""
    return Finding(
        scanner="semgrep",
        rule_id="rule",
        severity=Severity.HIGH,
        path="src/app.py",
        line=line,
        message="сообщение",
        finding_type=FindingType.SAST,
        fingerprint=fingerprint,
    )


# --- FR-003: обязательные поля и единая модель --------------------------------------


@pytest.mark.parametrize(
    ("scanner", "filename"),
    [
        ("semgrep", "semgrep.sarif"),
        ("gitleaks", "gitleaks.sarif"),
        ("trivy", "trivy.sarif"),
    ],
)
def test_fr_003_fixtures_give_complete_findings(scanner: str, filename: str) -> None:
    """Каждый сканер даёт находки, у которых все обязательные поля заполнены."""
    findings = normalize_run(_fixture_run(scanner, filename), FIXTURES)

    assert findings
    for finding in findings:
        assert finding.scanner == scanner
        assert finding.rule_id
        assert finding.path
        assert finding.message
        assert finding.fingerprint
        assert finding.line >= 1
        assert isinstance(finding.severity, Severity)
        assert isinstance(finding.finding_type, FindingType)


@pytest.mark.parametrize(
    ("scanner", "filename", "expected"),
    [
        ("semgrep", "semgrep.sarif", FindingType.SAST),
        ("gitleaks", "gitleaks.sarif", FindingType.SECRETS),
        ("trivy", "trivy.sarif", FindingType.DEPENDENCIES),
    ],
)
def test_fr_003_finding_type_follows_scanner(
    scanner: str, filename: str, expected: FindingType
) -> None:
    """Тип проверки берётся из имени сканера, а не из содержимого SARIF."""
    findings = normalize_run(_fixture_run(scanner, filename), FIXTURES)

    assert {finding.finding_type for finding in findings} == {expected}


@pytest.mark.parametrize(
    ("scanner", "filename", "rule_id", "expected"),
    [
        (
            "semgrep",
            "semgrep.sarif",
            "python.lang.security.audit.eval-detected",
            Severity.HIGH,
        ),
        (
            "semgrep",
            "semgrep.sarif",
            "python.lang.security.audit.hardcoded-password",
            Severity.MEDIUM,
        ),
        ("trivy", "trivy.sarif", "CVE-2023-12345", Severity.CRITICAL),
        ("trivy", "trivy.sarif", "CVE-2023-54321", Severity.MEDIUM),
    ],
)
def test_fr_003_severity_is_unified(
    scanner: str, filename: str, rule_id: str, expected: Severity
) -> None:
    """properties.severity важнее level; неизвестный уровень — medium."""
    findings = normalize_run(_fixture_run(scanner, filename), FIXTURES)

    severities = {finding.severity for finding in findings if finding.rule_id == rule_id}
    assert severities == {expected}


def test_fr_003_missing_region_falls_back_to_first_line() -> None:
    """Gitleaks не пишет регион: строка — первая, сообщение всё равно заполнено."""
    findings = normalize_run(_fixture_run("gitleaks", "gitleaks.sarif"), FIXTURES)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "aws-access-token"
    assert finding.line == 1
    assert finding.message


@pytest.mark.parametrize(
    "changes",
    [
        {"scanner": ""},
        {"rule_id": ""},
        {"path": ""},
        {"message": ""},
        {"fingerprint": ""},
        {"line": 0},
    ],
)
def test_fr_003_incomplete_finding_is_rejected(changes: dict[str, object]) -> None:
    """Пустое обязательное поле или строка меньше единицы — ошибка модели."""
    with pytest.raises(ValueError):
        replace(_finding(fingerprint="fingerprint"), **changes)


def test_fr_003_invalid_json_is_rejected(tmp_path: Path) -> None:
    """Невалидный JSON — ошибка нормализации на весь файл."""
    sarif = tmp_path / "broken.sarif"
    sarif.write_text("{это не json", encoding="utf-8")

    with pytest.raises(NormalizationError):
        normalize_run(_run("semgrep", sarif), tmp_path)


def test_fr_003_missing_runs_is_rejected(tmp_path: Path) -> None:
    """SARIF без runs — ошибка, а не пустой список находок."""
    sarif = tmp_path / "empty.sarif"
    sarif.write_text(json.dumps({"version": "2.1.0"}), encoding="utf-8")

    with pytest.raises(NormalizationError):
        normalize_run(_run("semgrep", sarif), tmp_path)


def test_fr_003_run_without_results_gives_no_findings(tmp_path: Path) -> None:
    """Поле results необязательно: чистый прогон даёт пустой список, а не ошибку."""
    sarif = tmp_path / "clean.sarif"
    sarif.write_text(
        json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}}]}),
        encoding="utf-8",
    )

    assert normalize_run(_run("semgrep", sarif), tmp_path) == []


def test_fr_003_result_without_location_data_is_rejected(tmp_path: Path) -> None:
    """Результат без locations, uri или ruleId — ошибка файла, а не пустое поле."""
    without_locations: dict[str, object] = {"ruleId": "rule", "message": {"text": "x"}}
    without_uri: dict[str, object] = {
        "ruleId": "rule",
        "message": {"text": "x"},
        "locations": [{"physicalLocation": {"artifactLocation": {}}}],
    }
    without_rule_id: dict[str, object] = {
        "message": {"text": "x"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}}},
        ],
    }

    for index, result in enumerate((without_locations, without_uri, without_rule_id)):
        sarif = _write_sarif(tmp_path / f"broken-{index}.sarif", result)
        with pytest.raises(NormalizationError):
            normalize_run(_run("semgrep", sarif), tmp_path)


def test_fr_003_missing_file_is_rejected() -> None:
    """Отсутствующий файл SARIF — ошибка нормализации, а не пустой результат."""
    with pytest.raises(NormalizationError):
        normalize_run(_run("semgrep", FIXTURES / "absent.sarif"), FIXTURES)


def test_fr_003_unknown_scanner_is_rejected() -> None:
    """Тип проверки не угадывается: неизвестное имя сканера — ошибка."""
    with pytest.raises(NormalizationError):
        normalize_run(_run("snyk", FIXTURES / "semgrep.sarif"), FIXTURES)


def test_fr_003_failed_run_gives_no_findings() -> None:
    """Упавший сканер не даёт находок: его результат — причина, а не SARIF."""
    run = ScannerRun(
        scanner="semgrep",
        status=ScannerStatus.FAILED,
        duration_ms=0,
        error="Инструмент завершился с кодом 1",
    )

    assert normalize_run(run, FIXTURES) == []


# --- FR-029: fingerprint и дедупликация --------------------------------------------


def test_fr_029_fingerprint_ignores_line_shift(tmp_path: Path) -> None:
    """Сдвиг кода меняет номер строки, но не fingerprint находки."""
    original = normalize_run(_fixture_run("semgrep", "semgrep.sarif"), FIXTURES)
    text = (FIXTURES / "semgrep.sarif").read_text(encoding="utf-8")
    shifted_sarif = tmp_path / "semgrep.sarif"
    shifted_sarif.write_text(
        text.replace('"startLine": 10', '"startLine": 99').replace(
            '"startLine": 42', '"startLine": 131'
        ),
        encoding="utf-8",
    )

    shifted = normalize_run(_run("semgrep", shifted_sarif), tmp_path)

    assert [finding.line for finding in shifted] == [99, 3]
    assert [finding.fingerprint for finding in shifted] == [
        finding.fingerprint for finding in original
    ]


def test_fr_029_duplicates_collapse_within_run() -> None:
    """Одно правило в одном файле с тем же фрагментом — одна находка."""
    findings = normalize_run(_fixture_run("semgrep", "semgrep.sarif"), FIXTURES)

    assert len(findings) == 2
    eval_findings = [
        finding
        for finding in findings
        if finding.rule_id == "python.lang.security.audit.eval-detected"
    ]
    assert len(eval_findings) == 1
    assert len({finding.fingerprint for finding in findings}) == len(findings)


def test_fr_029_deduplicate_keeps_first_occurrence_order() -> None:
    """Дедупликация оставляет первое вхождение и не меняет порядок."""
    first = _finding(fingerprint="a", line=1)
    second = _finding(fingerprint="b", line=2)
    duplicate = _finding(fingerprint="a", line=3)

    assert deduplicate([first, second, duplicate]) == [first, second]


def test_fr_029_fingerprint_depends_on_scanner() -> None:
    """Один и тот же текст от разных сканеров — разные находки."""
    semgrep = compute_fingerprint("semgrep", "rule", "src/app.py", "eval(x)")
    gitleaks = compute_fingerprint("gitleaks", "rule", "src/app.py", "eval(x)")

    assert semgrep != gitleaks


def test_fr_029_fingerprint_ignores_whitespace() -> None:
    """Пробелы и переводы строк во фрагменте не влияют на fingerprint."""
    spaced = compute_fingerprint("semgrep", "rule", "src/app.py", "a  b\n c")
    tight = compute_fingerprint("semgrep", "rule", "src/app.py", "a b c")

    assert normalize_snippet("a  b\n c") == "a b c"
    assert spaced == tight


@pytest.mark.parametrize("uri_template", ["{path}", "file://{path}"])
def test_fr_029_absolute_uri_becomes_relative_to_workdir(tmp_path: Path, uri_template: str) -> None:
    """Абсолютный и file:// uri приводятся к пути от корня клона."""
    workdir = tmp_path / "repo"
    target = workdir / "src" / "x.py"
    sarif = _write_sarif(
        tmp_path / "artifacts" / "custom.sarif",
        _result(uri=uri_template.format(path=target.as_posix())),
    )

    findings = normalize_run(_run("semgrep", sarif), workdir)

    assert [finding.path for finding in findings] == ["src/x.py"]
