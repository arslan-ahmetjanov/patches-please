"""Адаптеры Semgrep, Gitleaks и Trivy (T-013, FR-030).

Реальные бинарники не нужны: слой запуска подменяется, поэтому тесты проверяют
построение команды, трактовку кода возврата и проверку SARIF. Общий таймаут,
параллельность и изоляцию сбоя проверяет `tests/test_runner.py` (FR-028).
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from patches_please.scanners import process
from patches_please.scanners.base import ScannerRun, ScannerStatus
from patches_please.scanners.gitleaks import GitleaksAdapter
from patches_please.scanners.semgrep import SemgrepAdapter
from patches_please.scanners.trivy import TrivyAdapter

AdapterFactory = Callable[[], SemgrepAdapter | GitleaksAdapter | TrivyAdapter]


def _sarif(
    results: list[dict[str, Any]] | None = None, driver_version: str | None = "9.9.9"
) -> str:
    """Минимальный SARIF 2.1.0 с указанными результатами и версией драйвера."""
    driver: dict[str, str] = {"name": "fixture"}
    if driver_version is not None:
        driver["version"] = driver_version
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": driver},
                    "results": results or [],
                }
            ],
        }
    )


def _sarif_path(command: list[str]) -> Path:
    """Путь отчёта из команды: `--output` у Semgrep/Trivy, `--report-path` у Gitleaks."""
    flag = "--output" if "--output" in command else "--report-path"
    return Path(command[command.index(flag) + 1])


def _install_tool(
    monkeypatch: pytest.MonkeyPatch,
    *,
    code: int = 0,
    outcome: process.ProcessOutcome | None = None,
    write_sarif: bool = True,
    content: str | None = None,
    sarif_version: str | None = "9.9.9",
) -> list[tuple[list[str], float]]:
    """Подменяет запуск процесса, запоминая команды."""
    calls: list[tuple[list[str], float]] = []

    def fake_run(command: Any, timeout_sec: float) -> process.ProcessOutcome:
        command_list = list(command)
        calls.append((command_list, timeout_sec))
        if write_sarif:
            path = _sarif_path(command_list)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                content if content is not None else _sarif(driver_version=sarif_version),
                encoding="utf-8",
            )
        return outcome if outcome is not None else process.ProcessOutcome(returncode=code)

    monkeypatch.setattr(process, "run_process", fake_run)
    return calls


def _run(
    adapter: SemgrepAdapter | GitleaksAdapter | TrivyAdapter,
    workdir: Path,
    output_dir: Path,
    timeout_sec: float = 60.0,
) -> ScannerRun:
    """Запуск адаптера с каталогами теста."""
    return adapter.run(workdir, output_dir, timeout_sec)


# --- Команды инструментов ----------------------------------------------------------


def test_fr_030_semgrep_uses_local_rules_and_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Semgrep сканирует цель с локальными правилами, без метрик и проверки версии."""
    rules_dir = tmp_path / "rules"
    calls = _install_tool(monkeypatch)
    adapter = SemgrepAdapter(binary="semgrep-test", rules_dir=rules_dir)

    run = _run(adapter, tmp_path / "repo", tmp_path / "out", timeout_sec=42.0)

    assert run.status is ScannerStatus.OK
    command, timeout = calls[0]
    assert command[:2] == ["semgrep-test", "scan"]
    assert command[command.index("--config") + 1] == str(rules_dir)
    assert "--sarif" in command
    assert command[command.index("--output") + 1] == str(tmp_path / "out" / "semgrep.sarif")
    assert "--metrics=off" in command
    assert "--disable-version-check" in command
    assert "--quiet" in command
    assert command[-1] == str(tmp_path / "repo")
    assert timeout == pytest.approx(42.0)


def test_fr_030_semgrep_rules_dir_can_come_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Каталог правил можно переопределить переменной окружения образа."""
    rules_dir = tmp_path / "env-rules"
    monkeypatch.setenv("SEMGREP_RULES_DIR", str(rules_dir))
    calls = _install_tool(monkeypatch)

    _run(SemgrepAdapter(), tmp_path / "repo", tmp_path / "out")

    command, _ = calls[0]
    assert command[command.index("--config") + 1] == str(rules_dir)


def test_fr_030_trivy_cache_dir_can_come_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Каталог базы Trivy берётся из окружения, если не передан явно."""
    cache_dir = tmp_path / "env-cache"
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(cache_dir))
    calls = _install_tool(monkeypatch)

    _run(TrivyAdapter(), tmp_path / "repo", tmp_path / "out")

    command, _ = calls[0]
    assert command[command.index("--cache-dir") + 1] == str(cache_dir)


def test_fr_030_gitleaks_scans_directory_and_writes_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Gitleaks сканирует каталог, пишет SARIF и маскирует секрет в отчёте."""
    calls = _install_tool(monkeypatch)
    adapter = GitleaksAdapter(binary="gitleaks-test")

    run = _run(adapter, tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.OK
    command, _ = calls[0]
    assert command[:3] == ["gitleaks-test", "dir", str(tmp_path / "repo")]
    assert command[command.index("--report-format") + 1] == "sarif"
    assert command[command.index("--report-path") + 1] == str(tmp_path / "out" / "gitleaks.sarif")
    assert "--no-banner" in command
    assert "--redact" in command


def test_fr_030_trivy_scans_filesystem_with_offline_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Trivy сканирует файловую систему, не обновляет базу и проверяет только уязвимости."""
    cache_dir = tmp_path / "trivy-cache"
    calls = _install_tool(monkeypatch)
    adapter = TrivyAdapter(binary="trivy-test", cache_dir=cache_dir)

    run = _run(adapter, tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.OK
    command, _ = calls[0]
    assert command[:3] == ["trivy-test", "fs", str(tmp_path / "repo")]
    assert command[command.index("--format") + 1] == "sarif"
    assert command[command.index("--output") + 1] == str(tmp_path / "out" / "trivy.sarif")
    assert command[command.index("--scanners") + 1] == "vuln"
    assert command[command.index("--cache-dir") + 1] == str(cache_dir)
    assert "--skip-db-update" in command
    assert "--skip-java-db-update" in command


# --- Код возврата ------------------------------------------------------------------


@pytest.mark.parametrize("factory", [SemgrepAdapter, GitleaksAdapter])
def test_fr_030_findings_exit_code_one_is_ok(
    factory: AdapterFactory, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Код 1 у Semgrep и Gitleaks означает находки: валидный SARIF даёт `ok`."""
    _install_tool(monkeypatch, code=1)

    run = _run(factory(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.OK
    assert run.error is None
    assert run.sarif_path is not None


def test_fr_030_semgrep_failure_exit_code_is_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Код 2 у Semgrep — сбой инструмента, даже если файл SARIF создан."""
    _install_tool(monkeypatch, code=2)

    run = _run(SemgrepAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.FAILED
    assert run.sarif_path is None
    assert run.error is not None and "кодом 2" in run.error


def test_fr_030_trivy_non_zero_exit_code_is_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Для Trivy любой ненулевой код — сбой: находки он отмечает кодом 0."""
    _install_tool(monkeypatch, code=1)

    run = _run(TrivyAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.FAILED
    assert run.error is not None and "кодом 1" in run.error


# --- Отказы инструмента ------------------------------------------------------------


def test_fr_030_timeout_is_reported_as_timed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Таймаут процесса — статус `timed_out` с причиной без вывода инструмента."""
    _install_tool(monkeypatch, outcome=process.ProcessOutcome(returncode=-1, timed_out=True))

    run = _run(SemgrepAdapter(), tmp_path / "repo", tmp_path / "out", timeout_sec=2.0)

    assert run.status is ScannerStatus.TIMED_OUT
    assert run.error is not None and "таймаут" in run.error


def test_fr_030_launch_failure_is_reported_as_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Отсутствующий бинарник — `failed` с именем сканера, а не исключение."""
    _install_tool(monkeypatch, outcome=process.ProcessOutcome(returncode=-1, launch_failed=True))

    run = _run(GitleaksAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.FAILED
    assert run.error is not None and "gitleaks" in run.error


def test_fr_030_missing_sarif_is_failed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Код 0 без файла SARIF — не успех: нормализовать нечего."""
    _install_tool(monkeypatch, write_sarif=False)

    run = _run(TrivyAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.FAILED
    assert run.error is not None and "SARIF" in run.error


@pytest.mark.parametrize(
    "content",
    [
        "{не json",
        '{"version": "2.1.0"}',
        '{"version": "2.1.0", "runs": []}',
        '{"version": "2.0.0", "runs": [{}]}',
    ],
)
def test_fr_030_invalid_sarif_is_failed(
    content: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Битый, пустой или чужой SARIF — `failed`, а не `ok` с пустым отчётом."""
    _install_tool(monkeypatch, content=content)

    run = _run(SemgrepAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.status is ScannerStatus.FAILED
    assert run.error is not None and "некорректный SARIF" in run.error


def test_fr_030_stale_sarif_is_not_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Прошлый SARIF удаляется до запуска и не выдаётся за результат текущего."""
    output_dir = tmp_path / "out"
    stale = output_dir / "semgrep.sarif"
    stale.parent.mkdir(parents=True)
    stale.write_text(_sarif(), encoding="utf-8")
    _install_tool(monkeypatch, code=2, write_sarif=False)

    run = _run(SemgrepAdapter(), tmp_path / "repo", output_dir)

    assert run.status is ScannerStatus.FAILED
    assert not stale.exists()


# --- Метаданные результата ---------------------------------------------------------


def test_fr_030_version_is_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Версия инструмента сохраняется в результате для таблицы scanner_runs."""
    _install_tool(monkeypatch, sarif_version="1.2.3")

    run = _run(TrivyAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.tool_version == "1.2.3"


def test_fr_030_version_comes_from_build_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Без версии в SARIF она берётся из файла, записанного при сборке образа."""
    versions = tmp_path / "scanner-versions.json"
    versions.write_text(json.dumps({"semgrep": "1.186.0"}), encoding="utf-8")
    monkeypatch.setenv("SCANNER_VERSIONS_FILE", str(versions))
    _install_tool(monkeypatch, sarif_version=None)

    run = _run(SemgrepAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.tool_version == "1.186.0"


def test_fr_030_failure_reason_contains_no_tool_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Причина отказа — факт, а не текст инструмента: в нём могут быть секреты."""
    _install_tool(monkeypatch, code=2)

    run = _run(GitleaksAdapter(), tmp_path / "repo", tmp_path / "out")

    assert run.error is not None
    assert "ghp_" not in run.error
    assert "секрет" not in run.error
