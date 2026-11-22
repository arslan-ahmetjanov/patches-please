"""Параллельный запуск сканеров с общим таймаутом (T-011, FR-028).

Проверяется оркестратор на фейковых адаптерах: реальные инструменты, сеть и
бинарники не нужны. Адаптеры пишут пустой SARIF в каталог артефактов, спят
заданное время или падают — так проверяются параллельность, изоляция сбоя и
дедлайн без замера реальных сканеров.
"""

import logging
import threading
import time
from pathlib import Path

import pytest

from patches_please.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus
from patches_please.scanners.runner import DEFAULT_SCANNER_TIMEOUT_SEC, run_scanners
from patches_please.scans.queue import SCAN_JOB_TIMEOUT_SEC


def _ok_run(name: str, output_dir: Path, tool_version: str | None = "1.0") -> ScannerRun:
    """Успешный результат с настоящим файлом SARIF в каталоге артефактов."""
    sarif_path = output_dir / f"{name}.sarif"
    sarif_path.write_text("{}", encoding="utf-8")
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.OK,
        duration_ms=0,
        sarif_path=sarif_path,
        tool_version=tool_version,
    )


class OkAdapter:
    """Адаптер без инструмента: пишет пустой SARIF и возвращает `ok`."""

    def __init__(
        self,
        name: str,
        *,
        delay: float = 0.0,
        barrier: threading.Barrier | None = None,
        tool_version: str | None = "1.0",
    ) -> None:
        self.name = name
        self.delay = delay
        self.barrier = barrier
        self.tool_version = tool_version
        self.received_timeout: float | None = None

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        self.received_timeout = timeout_sec
        # Барьер пропускает только одновременный запуск: последовательный
        # оркестратор упрётся в таймаут ожидания и получит BrokenBarrierError.
        if self.barrier is not None:
            self.barrier.wait(timeout=5)
        if self.delay:
            time.sleep(self.delay)
        return _ok_run(self.name, output_dir, self.tool_version)


class RaisingAdapter:
    """Адаптер, который падает вместо запуска инструмента."""

    def __init__(self, name: str, exc: Exception) -> None:
        self.name = name
        self.exc = exc

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        raise self.exc


class FixedAdapter:
    """Адаптер, возвращающий заранее заданный результат."""

    def __init__(self, name: str, run: ScannerRun) -> None:
        self.name = name
        self._run = run

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        return self._run


# --- Параллельность ---------------------------------------------------------------


def test_fr_028_adapters_run_in_parallel(tmp_path: Path) -> None:
    """Три адаптера стартуют одновременно: барьер пропускает только всех сразу."""
    barrier = threading.Barrier(3)
    adapters: list[ScannerAdapter] = [
        OkAdapter("semgrep", barrier=barrier),
        OkAdapter("gitleaks", barrier=barrier),
        OkAdapter("trivy", barrier=barrier),
    ]

    started = time.monotonic()
    runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")
    elapsed = time.monotonic() - started

    assert [run.status for run in runs] == [ScannerStatus.OK] * 3
    assert elapsed < 5


def test_fr_028_adapters_receive_run_timeout(tmp_path: Path) -> None:
    """Адаптер получает общий таймаут запуска: им он ограничивает подпроцесс."""
    adapter = OkAdapter("semgrep")

    run_scanners([adapter], tmp_path, tmp_path / "artifacts", timeout_sec=12.5)

    assert adapter.received_timeout == pytest.approx(12.5)


# --- Изоляция сбоя ----------------------------------------------------------------


def test_fr_028_one_failure_does_not_stop_others(tmp_path: Path) -> None:
    """Падение одного сканера не мешает остальным завершиться."""
    adapters: list[ScannerAdapter] = [
        OkAdapter("semgrep"),
        RaisingAdapter("gitleaks", RuntimeError("сбой инструмента")),
        OkAdapter("trivy"),
    ]

    runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")

    assert [run.scanner for run in runs] == ["semgrep", "gitleaks", "trivy"]
    assert [run.status for run in runs] == [
        ScannerStatus.OK,
        ScannerStatus.FAILED,
        ScannerStatus.OK,
    ]
    assert runs[0].sarif_path is not None and runs[0].sarif_path.exists()
    assert runs[2].sarif_path is not None and runs[2].sarif_path.exists()


def test_fr_028_exception_becomes_failed_result_without_exception_text(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Исключение адаптера — результат `failed` с типом, но без текста (NFR-004)."""
    adapters: list[ScannerAdapter] = [
        RaisingAdapter("gitleaks", RuntimeError("токен ghp_оченьсекретный")),
    ]

    with caplog.at_level(logging.WARNING, logger="patches_please.scanners.runner"):
        runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")

    run = runs[0]
    assert run.status is ScannerStatus.FAILED
    assert run.sarif_path is None
    assert run.duration_ms >= 0
    assert run.error is not None
    assert "RuntimeError" in run.error
    assert "секрет" not in run.error
    assert "секрет" not in caplog.text


def test_fr_028_adapter_failure_status_is_preserved(tmp_path: Path) -> None:
    """Отказ инструмента без исключения сохраняется как `failed` с причиной."""
    reported = ScannerRun(
        scanner="trivy",
        status=ScannerStatus.FAILED,
        duration_ms=0,
        error="Инструмент завершился с кодом 1",
    )
    adapters: list[ScannerAdapter] = [FixedAdapter("trivy", reported)]

    runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")

    assert runs[0].status is ScannerStatus.FAILED
    assert runs[0].error == "Инструмент завершился с кодом 1"
    assert runs[0].sarif_path is None


# --- Общий таймаут ----------------------------------------------------------------


def test_fr_028_deadline_marks_unfinished_timed_out_and_keeps_finished(tmp_path: Path) -> None:
    """По дедлайну ожидание прекращается: готовые результаты остаются, прочие `timed_out`."""
    fast = OkAdapter("semgrep")
    slow = OkAdapter("trivy", delay=2.0)

    started = time.monotonic()
    runs = run_scanners([fast, slow], tmp_path, tmp_path / "artifacts", timeout_sec=0.5)
    elapsed = time.monotonic() - started

    assert elapsed < 1.5
    assert runs[0].status is ScannerStatus.OK
    assert runs[1].status is ScannerStatus.TIMED_OUT
    assert runs[1].sarif_path is None
    assert runs[1].duration_ms >= 400
    assert runs[1].error is not None
    assert "0.5" in runs[1].error


def test_fr_028_timeout_is_shorter_than_job_timeout() -> None:
    """Общий таймаут сканеров меньше таймаута задачи, иначе RQ прервёт её раньше."""
    assert DEFAULT_SCANNER_TIMEOUT_SEC == 300
    assert DEFAULT_SCANNER_TIMEOUT_SEC < SCAN_JOB_TIMEOUT_SEC


@pytest.mark.parametrize("timeout_sec", [0, -1.0])
def test_fr_028_non_positive_timeout_is_rejected(tmp_path: Path, timeout_sec: float) -> None:
    """Нулевой и отрицательный таймаут — ошибка вызова, а не мгновенный дедлайн."""
    with pytest.raises(ValueError):
        run_scanners([OkAdapter("semgrep")], tmp_path, tmp_path / "artifacts", timeout_sec)


# --- Содержимое результата --------------------------------------------------------


def test_fr_028_success_reports_sarif_path_version_and_duration(tmp_path: Path) -> None:
    """Успешный результат несёт путь к SARIF, версию инструмента и длительность."""
    output_dir = tmp_path / "nested" / "artifacts"

    runs = run_scanners([OkAdapter("semgrep", tool_version="1.2.3")], tmp_path, output_dir)

    run = runs[0]
    assert run.status is ScannerStatus.OK
    assert run.scanner == "semgrep"
    assert run.sarif_path == output_dir / "semgrep.sarif"
    assert run.sarif_path.exists()
    assert run.tool_version == "1.2.3"
    assert run.duration_ms >= 0
    assert run.error is None


def test_fr_028_results_keep_adapter_order(tmp_path: Path) -> None:
    """Результаты идут в порядке адаптеров, а не в порядке завершения."""
    adapters: list[ScannerAdapter] = [
        OkAdapter("slow", delay=0.2),
        OkAdapter("fast"),
        OkAdapter("medium", delay=0.1),
    ]

    runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")

    assert [run.scanner for run in runs] == ["slow", "fast", "medium"]


def test_fr_028_name_and_duration_come_from_orchestrator(tmp_path: Path) -> None:
    """Имя и длительность задаёт оркестратор: адаптер не искажает метрику прогона."""
    reported = ScannerRun(
        scanner="чужое имя",
        status=ScannerStatus.OK,
        duration_ms=999_000,
        sarif_path=tmp_path / "trivy.sarif",
    )
    adapters: list[ScannerAdapter] = [FixedAdapter("trivy", reported)]

    runs = run_scanners(adapters, tmp_path, tmp_path / "artifacts")

    assert runs[0].scanner == "trivy"
    assert runs[0].duration_ms < 60_000


def test_fr_028_empty_adapter_list_returns_nothing(tmp_path: Path) -> None:
    """Пустой список адаптеров — пустой результат без создания каталога."""
    output_dir = tmp_path / "artifacts"

    assert run_scanners([], tmp_path, output_dir) == []
    assert not output_dir.exists()
