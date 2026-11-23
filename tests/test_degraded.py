"""Деградация проверки и режим отказа (T-019, FR-013, S-004).

Сценарий S-004: сканер падает или превышает таймаут — проверка помечается
`degraded` с причиной, а вердикт следует режиму политики. При `fail-open` прогон
не блокируется и считается по оставшимся проверкам; при `fail-closed` неполная
проверка даёт `fail` даже без находок.

Тесты чистые: `ScannerRun` и `ProjectPolicy` собираются в памяти, база не нужна.
Сквозной проход через воркер и запись вердикта — T-038; здесь только расчёт.
То, что `degraded` не стало третьим вердиктом, проверяет
`tests/test_cli.py::test_fr_033_exit_four_on_unknown_verdict` (FR-033).
"""

import uuid
from pathlib import Path

from patches_please.normalize.model import FindingType, Severity
from patches_please.policy.classify import FindingState
from patches_please.policy.degraded import (
    DEGRADED_STATUSES,
    degraded_checks,
    is_degraded,
    verdict_with_degradation,
)
from patches_please.policy.verdict import DEFAULT_POLICY, FailMode, ProjectPolicy, Verdict
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scans.models import FindingRecord

FAILURE_REASON = "Сканер завершился исключением: FileNotFoundError"
TIMEOUT_REASON = "Превышен общий таймаут сканеров (300 с)"
ARTIFACTS = Path("artifacts")


def _policy(fail_mode: FailMode) -> ProjectPolicy:
    """Политика проекта: пороги по умолчанию, меняется только режим отказа."""
    return ProjectPolicy(
        block_severities=DEFAULT_POLICY.block_severities,
        fail_mode=fail_mode,
        scanner_timeout_sec=DEFAULT_POLICY.scanner_timeout_sec,
    )


def _ok(name: str) -> ScannerRun:
    """Успешный запуск: путь к SARIF есть, причины нет."""
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.OK,
        duration_ms=12,
        sarif_path=ARTIFACTS / f"{name}.sarif",
        tool_version="1.0",
    )


def _failed(name: str = "gitleaks") -> ScannerRun:
    """Сканер завершился ошибкой: причина без текста исключения (NFR-004)."""
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.FAILED,
        duration_ms=40,
        error=FAILURE_REASON,
    )


def _timed_out(name: str = "trivy") -> ScannerRun:
    """Сканер не уложился в общий таймаут."""
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.TIMED_OUT,
        duration_ms=300_000,
        error=TIMEOUT_REASON,
    )


def _record(
    *,
    severity: Severity = Severity.HIGH,
    state: FindingState = FindingState.NEW,
    excluded: bool = False,
) -> FindingRecord:
    """Несохранённая строка находки для чистой проверки вердикта."""
    return FindingRecord(
        scan_id=uuid.uuid4(),
        fingerprint="f" * 64,
        scanner="semgrep",
        rule_id="rule-1",
        finding_type=str(FindingType.SAST),
        severity=str(severity),
        path="src/app.py",
        line=1,
        message="Опасный вызов",
        state=str(state),
        excluded=excluded,
    )


# --- FR-013: пометка degraded и причина -------------------------------------------


def test_fr_013_failed_scanner_is_degraded_with_reason() -> None:
    """Упавший сканер помечен `degraded`, причина сохранена в результате запуска."""
    run = _failed()

    assert is_degraded(run)
    assert [check.scanner for check in degraded_checks([run])] == ["gitleaks"]
    assert [check.error for check in degraded_checks([run])] == [FAILURE_REASON]


def test_fr_013_timed_out_scanner_is_degraded_with_reason() -> None:
    """Просроченный сканер — тоже деградация, и причина — таймаут."""
    run = _timed_out()

    assert is_degraded(run)
    assert [check.error for check in degraded_checks([run])] == [TIMEOUT_REASON]


def test_fr_013_successful_scanner_is_not_degraded() -> None:
    """Отработавший сканер деградацией не считается."""
    run = _ok("semgrep")

    assert not is_degraded(run)
    assert degraded_checks([run]) == ()


def test_fr_013_degraded_checks_keep_run_order() -> None:
    """Пометки идут в порядке запуска, успешный сканер в список не попадает."""
    runs = [_ok("semgrep"), _failed("gitleaks"), _timed_out("trivy")]

    assert [run.scanner for run in degraded_checks(runs)] == ["gitleaks", "trivy"]


def test_fr_013_degraded_marks_are_only_failures_and_timeouts() -> None:
    """Множество деградировавших статусов — ровно `failed` и `timed_out`."""
    assert {ScannerStatus.FAILED, ScannerStatus.TIMED_OUT} == DEGRADED_STATUSES


# --- FR-013, S-004: fail-open не блокирует ---------------------------------------


def test_fr_013_fail_open_does_not_block_on_failed_scanner() -> None:
    """S-004: упавший сканер при fail-open не блокирует пайплайн."""
    verdict = verdict_with_degradation([], _policy(FailMode.OPEN), [_failed()])

    assert verdict is Verdict.PASS


def test_fr_013_fail_open_does_not_block_on_timed_out_scanner() -> None:
    """Просроченный сканер при fail-open тоже не блокирует."""
    verdict = verdict_with_degradation([], _policy(FailMode.OPEN), [_timed_out()])

    assert verdict is Verdict.PASS


def test_fr_013_fail_open_still_blocks_on_new_blocking_finding() -> None:
    """Fail-open не отменяет FR-005: новая `critical` по-прежнему даёт `fail`."""
    runs = [_ok("semgrep"), _failed("gitleaks")]

    verdict = verdict_with_degradation(
        [_record(severity=Severity.CRITICAL)], _policy(FailMode.OPEN), runs
    )

    assert verdict is Verdict.FAIL


def test_fr_013_fail_open_ignores_findings_below_threshold() -> None:
    """Fail-open считает находки как раньше: `medium` при умолчании не блокирует."""
    verdict = verdict_with_degradation(
        [_record(severity=Severity.MEDIUM)], _policy(FailMode.OPEN), [_failed()]
    )

    assert verdict is Verdict.PASS


def test_s_004_partial_coverage_keeps_findings_of_remaining_scanners() -> None:
    """Частичное покрытие: находки отработавших сканеров учитываются, причина видна."""
    policy = _policy(FailMode.OPEN)
    runs = [_ok("semgrep"), _failed("gitleaks")]
    records = [_record(severity=Severity.CRITICAL)]

    assert verdict_with_degradation(records, policy, runs) is Verdict.FAIL
    assert [run.scanner for run in degraded_checks(runs)] == ["gitleaks"]


# --- FR-013: fail-closed блокирует -------------------------------------------------


def test_fr_013_fail_closed_blocks_on_failed_scanner() -> None:
    """При fail-closed упавший сканер даёт `fail` даже без находок."""
    verdict = verdict_with_degradation([], _policy(FailMode.CLOSED), [_failed()])

    assert verdict is Verdict.FAIL


def test_fr_013_fail_closed_blocks_on_timed_out_scanner() -> None:
    """При fail-closed просроченный сканер даёт `fail` даже без находок."""
    verdict = verdict_with_degradation([], _policy(FailMode.CLOSED), [_timed_out()])

    assert verdict is Verdict.FAIL


def test_fr_013_fail_closed_is_not_masked_by_clean_findings() -> None:
    """Находки ниже порога не превращают неполную проверку в `pass`."""
    verdict = verdict_with_degradation(
        [_record(severity=Severity.MEDIUM)], _policy(FailMode.CLOSED), [_failed()]
    )

    assert verdict is Verdict.FAIL


def test_fr_013_fail_closed_without_degradation_counts_findings() -> None:
    """Без деградации fail-closed не влияет: вердикт считают находки."""
    policy = _policy(FailMode.CLOSED)
    runs = [_ok("semgrep"), _ok("gitleaks"), _ok("trivy")]

    assert verdict_with_degradation([], policy, runs) is Verdict.PASS
    assert (
        verdict_with_degradation([_record(severity=Severity.CRITICAL)], policy, runs)
        is Verdict.FAIL
    )
