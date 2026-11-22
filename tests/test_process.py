"""Запуск внешнего процесса сканера (T-013, FR-030).

Проверяется общий слой адаптеров: команда передаётся списком без оболочки,
вывод не читается, таймаут завершает процесс, ошибка запуска не превращается в
исключение. Реальные сканеры и сеть не нужны: используется текущий Python.
"""

import json
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from app.scanners import process


def test_fr_030_success_returns_exit_code() -> None:
    """Успешный процесс возвращает свой код без исключения."""
    outcome = process.run_process([sys.executable, "-c", "raise SystemExit(0)"], 5.0)

    assert outcome.returncode == 0
    assert not outcome.timed_out
    assert not outcome.launch_failed


def test_fr_030_non_zero_exit_code_is_returned() -> None:
    """Ненулевой код — данные для адаптера, а не сбой слоя запуска."""
    outcome = process.run_process([sys.executable, "-c", "raise SystemExit(3)"], 5.0)

    assert outcome.returncode == 3
    assert not outcome.timed_out


def test_fr_030_timeout_terminates_process() -> None:
    """По таймауту процесс завершается, ожидание не тянется до конца команды."""
    started = time.monotonic()
    outcome = process.run_process(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        0.2,
    )
    elapsed = time.monotonic() - started

    assert outcome.timed_out
    assert elapsed < 5


def test_fr_030_missing_binary_is_launch_failure() -> None:
    """Отсутствующий бинарник — результат `launch_failed`, а не исключение."""
    outcome = process.run_process(["security-gate-missing-scanner"], 1.0)

    assert outcome.launch_failed
    assert not outcome.timed_out


def test_fr_030_non_positive_timeout_is_rejected() -> None:
    """Нулевой таймаут — ошибка вызова: запускать процесс без предела нельзя."""
    with pytest.raises(ValueError):
        process.run_process([sys.executable, "-c", "pass"], 0)


def test_fr_030_command_is_a_list_without_shell_and_without_output_capture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Команда идёт списком, без `shell`; stdout и stderr направлены в DEVNULL."""
    captured: dict[str, Any] = {}

    class FakeProcess:
        pid = 12345

        def wait(self, timeout: float | None = None) -> int:
            captured["timeout"] = timeout
            return 0

    def fake_popen(command: list[str], **kwargs: Any) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    command = [sys.executable, "-c", "print('a & b')"]

    outcome = process.run_process(command, 7.0)

    assert outcome.returncode == 0
    assert captured["command"] == command
    assert not captured["kwargs"].get("shell", False)
    assert captured["kwargs"]["stdout"] is subprocess.DEVNULL
    assert captured["kwargs"]["stderr"] is subprocess.DEVNULL
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert captured["timeout"] == pytest.approx(7.0)


def test_fr_030_tool_output_does_not_reach_logs(caplog: pytest.LogCaptureFixture) -> None:
    """Секрет из stdout/stderr инструмента не попадает в журнал слоя запуска."""
    script = "import sys; print('SECRET_OUTPUT'); print('SECRET_ERROR', file=sys.stderr)"

    with caplog.at_level(logging.DEBUG):
        outcome = process.run_process([sys.executable, "-c", script], 5.0)

    assert outcome.returncode == 0
    assert "SECRET_OUTPUT" not in caplog.text
    assert "SECRET_ERROR" not in caplog.text


def _sarif_document(driver_version: str | None) -> str:
    """SARIF с версией драйвера или без неё, как у Semgrep и Gitleaks."""
    driver: dict[str, str] = {"name": "fixture"}
    if driver_version is not None:
        driver["version"] = driver_version
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": driver}, "results": []}]})


def test_fr_030_read_tool_version_from_sarif_driver(tmp_path: Path) -> None:
    """Trivy пишет версию в SARIF: она важнее файла сборки."""
    sarif = tmp_path / "trivy.sarif"
    sarif.write_text(_sarif_document("0.76.2"), encoding="utf-8")
    versions = tmp_path / "versions.json"
    versions.write_text('{"trivy": "9.9.9"}', encoding="utf-8")

    assert process.read_tool_version(sarif, "trivy", versions_path=versions) == "0.76.2"


def test_fr_030_read_tool_version_from_build_file(tmp_path: Path) -> None:
    """Semgrep и Gitleaks не пишут версию в SARIF: берётся файл сборки."""
    sarif = tmp_path / "semgrep.sarif"
    sarif.write_text(_sarif_document(None), encoding="utf-8")
    versions = tmp_path / "versions.json"
    versions.write_text(json.dumps({"semgrep": "1.186.0"}), encoding="utf-8")

    assert process.read_tool_version(sarif, "semgrep", versions_path=versions) == "1.186.0"


def test_fr_030_read_tool_version_without_sources_is_none(tmp_path: Path) -> None:
    """Нет версии ни в SARIF, ни в файле — метаданные остаются неизвестными."""
    sarif = tmp_path / "gitleaks.sarif"
    sarif.write_text(_sarif_document(None), encoding="utf-8")

    assert (
        process.read_tool_version(sarif, "gitleaks", versions_path=tmp_path / "missing.json")
        is None
    )


def test_fr_030_sarif_must_be_object_with_runs(tmp_path: Path) -> None:
    """Валидным считается только SARIF 2.1.0 с непустым списком runs."""
    valid = tmp_path / "valid.sarif"
    valid.write_text('{"version": "2.1.0", "runs": [{}]}', encoding="utf-8")
    assert process.is_valid_sarif(valid)

    for name, content in {
        "not-json.sarif": "{",
        "no-runs.sarif": '{"version": "2.1.0"}',
        "empty-runs.sarif": '{"version": "2.1.0", "runs": []}',
        "wrong-version.sarif": '{"version": "2.0.0", "runs": [{}]}',
        "array.sarif": "[]",
    }.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        assert not process.is_valid_sarif(path), name

    assert not process.is_valid_sarif(tmp_path / "missing.sarif")
