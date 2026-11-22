"""Запуск внешнего инструмента сканера и проверка его SARIF (T-013, FR-030).

Адаптеры не вызывают `subprocess` напрямую: вся работа с процессом собрана здесь,
чтобы одинаково ограничивать время, не читать вывод инструмента в память и не
писать его в лог. Содержимое находок и сообщений об ошибках инструмента может
содержать секреты (NFR-004), поэтому stdout и stderr уходят в `/dev/null`, а в
`ScannerRun.error` попадает только факт: код возврата, отсутствие или
некорректность SARIF, таймаут.

Команда всегда передаётся списком аргументов, `shell=True` не используется:
путь к сканируемому репозиторию не должен попадать в разбор оболочки. Подпроцесс
запускается в отдельной сессии, поэтому по таймауту завершается вся группа
процессов, а не только прямой потомок: semgrep запускает `semgrep-core`, и без
этого осиротевший процесс продолжал бы работу после `timed_out`.
"""

import json
import os
import signal
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from patches_please.scanners.base import ScannerRun, ScannerStatus

# Предел ожидания завершения процесса после SIGKILL.
TERMINATION_TIMEOUT_SEC: Final = 5.0
VERSION_MAX_LENGTH: Final = 80
SARIF_REQUIRED_VERSION: Final = "2.1.0"
# Файл с версиями, записанными при сборке: Semgrep и Gitleaks не пишут версию
# в SARIF, а запускать `--version` в офлайне нельзя — Semgrep не завершается.
DEFAULT_VERSIONS_FILE: Final = Path("/opt/scanner-versions.json")
TIMEOUT_REASON_TEMPLATE: Final = "Сканер не уложился в таймаут ({timeout:g} с)"
LAUNCH_REASON_TEMPLATE: Final = "Инструмент сканера не запустился: {name}"
EXIT_REASON_TEMPLATE: Final = "Инструмент завершился с кодом {code}"
MISSING_SARIF_TEMPLATE: Final = "Инструмент не создал файл SARIF: {name}"
INVALID_SARIF_TEMPLATE: Final = "Инструмент создал некорректный SARIF: {name}"


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    """Итог подпроцесса без его вывода: только код и характер завершения."""

    returncode: int
    timed_out: bool = False
    launch_failed: bool = False


def run_process(command: Sequence[str], timeout_sec: float) -> ProcessOutcome:
    """Запускает команду без оболочки и возвращает только код завершения.

    `timeout_sec` — предел на весь процесс; по истечении завершается группа
    процессов. Вывод инструмента не читается: он не нужен и не должен попасть
    в лог. Ошибка запуска (нет бинарника, нет прав) — результат, а не исключение:
    оркестратор ждёт `ScannerRun` по каждому адаптеру.
    """
    if timeout_sec <= 0:
        raise ValueError("Таймаут инструмента должен быть положительным")
    try:
        process = subprocess.Popen(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name != "nt",
        )
    except OSError:
        return ProcessOutcome(returncode=-1, launch_failed=True)
    try:
        return ProcessOutcome(returncode=process.wait(timeout=timeout_sec))
    except subprocess.TimeoutExpired:
        _terminate(process)
        return ProcessOutcome(returncode=-1, timed_out=True)


def read_tool_version(
    sarif_path: Path,
    scanner: str,
    versions_path: Path | None = None,
) -> str | None:
    """Возвращает версию инструмента для `ScannerRun.tool_version`.

    Сначала берётся `runs[0].tool.driver.version` из SARIF: так Trivy сообщает
    точную версию, создавшую отчёт. Semgrep и Gitleaks это поле не заполняют,
    поэтому запасной источник — JSON с версиями, записанный при сборке образа
    (`/opt/scanner-versions.json`). Отдельный `--version` не запускается:
    Semgrep в офлайне печатает версию, но не завершается, и запрос повисал бы
    до таймаута.
    """
    document = _load_document(sarif_path)
    version = _sarif_driver_version(document)
    if version is not None:
        return version
    path = versions_path or Path(
        os.environ.get("SCANNER_VERSIONS_FILE", str(DEFAULT_VERSIONS_FILE))
    )
    try:
        versions = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(versions, dict):
        return None
    value = versions.get(scanner)
    if isinstance(value, str) and value.strip():
        return value.strip()[:VERSION_MAX_LENGTH]
    return None


def is_valid_sarif(path: Path) -> bool:
    """Проверяет, что файл — SARIF 2.1.0 с непустым списком `runs`.

    Полную проверку полей делает нормализатор (FR-029). Здесь достаточно
    отличить созданный инструментом отчёт от отсутствующего, обрезанного или
    постороннего файла: адаптер не должен вернуть `ok` без пригодного SARIF.
    """
    document = _load_document(path)
    if document is None:
        return False
    if document.get("version") != SARIF_REQUIRED_VERSION:
        return False
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        return False
    return all(isinstance(run, dict) for run in runs)


def _load_document(path: Path) -> dict[str, object] | None:
    """Читает SARIF как объект JSON; любая проблема — `None` без текста (NFR-004)."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _sarif_driver_version(document: dict[str, object] | None) -> str | None:
    """Версия драйвера из первого run SARIF, если инструмент её заполнил."""
    if document is None:
        return None
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        return None
    first_run = runs[0]
    if not isinstance(first_run, dict):
        return None
    tool = first_run.get("tool")
    if not isinstance(tool, dict):
        return None
    driver = tool.get("driver")
    if not isinstance(driver, dict):
        return None
    version = driver.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()[:VERSION_MAX_LENGTH]
    return None


def execute_tool(
    *,
    name: str,
    command: Sequence[str],
    sarif_path: Path,
    timeout_sec: float,
    allowed_exit_codes: frozenset[int],
) -> ScannerRun:
    """Запускает инструмент и превращает итог в `ScannerRun`.

    Код возврата сам по себе не признак сбоя: semgrep и gitleaks возвращают 1,
    когда нашли проблемы. Успех — допустимый код и валидный SARIF; всё
    остальное даёт `failed` с причиной без вывода инструмента. Имя и
    длительность результата всё равно заменит оркестратор (FR-028).
    """
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    # Старый файл удаляется заранее: иначе сбой инструмента мог бы выдать
    # прошлый SARIF за результат текущего запуска.
    sarif_path.unlink(missing_ok=True)
    outcome = run_process(command, timeout_sec)
    if outcome.timed_out:
        return _failure(
            name,
            TIMEOUT_REASON_TEMPLATE.format(timeout=timeout_sec),
            status=ScannerStatus.TIMED_OUT,
        )
    if outcome.launch_failed:
        return _failure(name, LAUNCH_REASON_TEMPLATE.format(name=name))
    if outcome.returncode not in allowed_exit_codes:
        return _failure(name, EXIT_REASON_TEMPLATE.format(code=outcome.returncode))
    if not sarif_path.is_file():
        return _failure(name, MISSING_SARIF_TEMPLATE.format(name=name))
    if not is_valid_sarif(sarif_path):
        return _failure(name, INVALID_SARIF_TEMPLATE.format(name=name))
    return ScannerRun(
        scanner=name,
        status=ScannerStatus.OK,
        duration_ms=0,
        sarif_path=sarif_path,
        tool_version=read_tool_version(sarif_path, name),
    )


def _failure(
    name: str,
    reason: str,
    status: ScannerStatus = ScannerStatus.FAILED,
) -> ScannerRun:
    """Неуспешный результат с причиной и без пути к SARIF."""
    return ScannerRun(
        scanner=name,
        status=status,
        duration_ms=0,
        error=reason,
    )


def _terminate(process: subprocess.Popen[bytes]) -> None:
    """Завершает группу процессов и дожидается её, не оставляя сирот.

    `os.killpg`, `os.getpgid` и `signal.SIGKILL` есть только в POSIX; на Windows
    завершается прямой потомок. Атрибуты берутся из `__dict__`, потому что mypy
    на Windows не объявляет POSIX-функции, а на Linux они нужны.
    """
    kill_group = os.__dict__.get("killpg")
    get_group = os.__dict__.get("getpgid")
    sigkill = signal.__dict__.get("SIGKILL")
    try:
        if os.name == "nt" or kill_group is None or get_group is None or sigkill is None:
            process.kill()
        else:
            kill_group(get_group(process.pid), sigkill)
    except OSError:
        process.kill()
    try:
        process.wait(timeout=TERMINATION_TIMEOUT_SEC)
    except subprocess.TimeoutExpired:
        process.kill()
