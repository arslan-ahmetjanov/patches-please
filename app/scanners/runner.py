"""Параллельный запуск адаптеров сканеров с общим таймаутом (T-011, FR-028).

Сканеры независимы, поэтому запускаются одновременно в пуле потоков: прогон
ждёт самый долгий инструмент, а не сумму всех. Общий дедлайн считается по
`time.monotonic()` от старта; адаптеры получают его как `timeout_sec`, а по
истечении дедлайна незавершённые помечаются `timed_out` — ожидание
прекращается, уже готовые результаты сохраняются.

Сбой одного сканера не отменяет остальные: исключение адаптера превращается в
`ScannerRun` со статусом `failed`. Текст исключения в причину не попадает: в нём
могут оказаться путь, URL или токен (NFR-004), поэтому в причине только имя
типа, как в обработчике сбоя задачи (FR-027).

Общий таймаут меньше таймаута задачи (`SCAN_JOB_TIMEOUT_SEC = 600` с, FR-027),
чтобы оркестратор вернул частичные результаты до того, как RQ прервёт задачу.
"""

import logging
from collections.abc import Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import replace
from pathlib import Path
from time import monotonic
from typing import Final

from app.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus

logger = logging.getLogger(__name__)

# Время на весь запуск сканеров: меньше SCAN_JOB_TIMEOUT_SEC (600 с, FR-027).
DEFAULT_SCANNER_TIMEOUT_SEC: Final = 300
EXCEPTION_REASON_TEMPLATE: Final = "Сканер завершился исключением: {name}"
TIMEOUT_REASON_TEMPLATE: Final = "Превышен общий таймаут сканеров ({timeout:g} с)"


def run_scanners(
    adapters: Sequence[ScannerAdapter],
    workdir: Path,
    output_dir: Path,
    timeout_sec: float = DEFAULT_SCANNER_TIMEOUT_SEC,
) -> list[ScannerRun]:
    """Запускает адаптеры параллельно и возвращает результат по каждому.

    Результаты идут в порядке `adapters`, даже если инструменты завершились в
    другом порядке. Имя и длительность в результате ставит оркестратор: адаптер
    не может исказить метрику прогона. `output_dir` создаётся заранее — туда
    адаптеры пишут SARIF.
    """
    if timeout_sec <= 0:
        raise ValueError("Таймаут сканеров должен быть положительным")
    if not adapters:
        return []
    output_dir.mkdir(parents=True, exist_ok=True)
    started = monotonic()
    deadline = started + timeout_sec
    completed: dict[int, ScannerRun] = {}
    pending: dict[Future[ScannerRun], int] = {}
    executor = ThreadPoolExecutor(max_workers=len(adapters), thread_name_prefix="scanner")
    try:
        for index, adapter in enumerate(adapters):
            pending[executor.submit(adapter.run, workdir, output_dir, timeout_sec)] = index
        while pending:
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            done, _ = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            if not done:
                break
            for future in done:
                index = pending.pop(future)
                completed[index] = _collect(adapters[index], future, started)
    finally:
        # Поток прервать нельзя: незавершённый адаптер доработает в фоне до
        # своего предела, но оркестратор его не ждёт — иначе общий таймаут
        # теряет смысл.
        executor.shutdown(wait=False, cancel_futures=True)

    elapsed_ms = _elapsed_ms(started)
    runs: list[ScannerRun] = []
    for index, adapter in enumerate(adapters):
        run = completed.get(index)
        if run is None:
            logger.warning("сканер не уложился в общий таймаут", extra={"scanner": adapter.name})
            run = ScannerRun(
                scanner=adapter.name,
                status=ScannerStatus.TIMED_OUT,
                duration_ms=elapsed_ms,
                error=TIMEOUT_REASON_TEMPLATE.format(timeout=timeout_sec),
            )
        runs.append(run)
        logger.info(
            "сканер завершён: %s, %s, %s мс",
            run.scanner,
            run.status,
            run.duration_ms,
            extra={"scanner": run.scanner, "duration_ms": run.duration_ms},
        )
    return runs


def _collect(adapter: ScannerAdapter, future: Future[ScannerRun], started: float) -> ScannerRun:
    """Превращает завершение адаптера в результат, не пропуская исключения."""
    try:
        run = future.result()
    except Exception as exc:
        # Сбой одного сканера не должен ломать прогон и терять чужие результаты.
        # Трассировка не пишется: текст исключения может содержать секреты (NFR-004).
        logger.warning("сканер завершился исключением: %s", type(exc).__name__)
        return ScannerRun(
            scanner=adapter.name,
            status=ScannerStatus.FAILED,
            duration_ms=_elapsed_ms(started),
            error=EXCEPTION_REASON_TEMPLATE.format(name=type(exc).__name__),
        )
    return replace(run, scanner=adapter.name, duration_ms=_elapsed_ms(started))


def _elapsed_ms(started: float) -> int:
    """Миллисекунды от старта запуска: целые, неотрицательные."""
    return max(0, int((monotonic() - started) * 1000))
