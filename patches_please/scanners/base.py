"""Общий интерфейс адаптера сканера (T-011, FR-028).

Адаптер — тонкая обёртка над одним инструментом: он знает команду запуска,
куда положить SARIF и как прочитать версию. Оркестратор (`patches_please.scanners.runner`)
ничего не знает про конкретные инструменты: он запускает адаптеры параллельно,
следит за общим дедлайном и превращает сбой одного адаптера в результат, а не
в исключение.

`ScannerRun` — единственная форма, в которой результат запуска уходит дальше:
нормализации (T-012) нужен путь к SARIF, а отчёту и таблице `scanner_runs` —
статус, длительность и версия инструмента.
"""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol


class ScannerStatus(StrEnum):
    """Исход одного запуска сканера."""

    OK = "ok"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class ScannerRun:
    """Результат запуска одного адаптера.

    Для `ok` обязателен `sarif_path`: без файла нормализовать нечего.
    Для `failed` и `timed_out` обязательна непустая причина `error`: она нужна
    отчёту и таблице `scanner_runs`. Текст причины не содержит вывода
    инструмента и текста исключения — только тип или факт таймаута (NFR-004).
    """

    scanner: str
    status: ScannerStatus
    duration_ms: int
    sarif_path: Path | None = None
    error: str | None = None
    tool_version: str | None = None

    def __post_init__(self) -> None:
        if not self.scanner:
            raise ValueError("Имя сканера не может быть пустым")
        if self.duration_ms < 0:
            raise ValueError("Длительность сканера не может быть отрицательной")
        if self.status is ScannerStatus.OK:
            if self.sarif_path is None:
                raise ValueError("Успешный запуск сканера должен указывать путь к SARIF")
            if self.error is not None:
                raise ValueError("Успешный запуск сканера не содержит ошибки")
        elif not self.error:
            raise ValueError("Неуспешный запуск сканера должен содержать причину")


class ScannerAdapter(Protocol):
    """Структурный интерфейс адаптера: имя для отчёта и один запуск инструмента.

    `run` получает рабочий каталог с кодом и каталог для артефактов; `timeout_sec`
    — предел времени на запуск. Адаптер сам ограничивает подпроцесс этим
    временем (T-013): поток оркестратора прервать нельзя.

    Наследование не требуется: достаточно атрибута `name` и метода `run`.
    """

    name: str

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun: ...
