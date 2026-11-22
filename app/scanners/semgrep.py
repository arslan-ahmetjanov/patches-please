"""Адаптер Semgrep: статический анализ кода (T-013, FR-002, FR-030).

Semgrep запускается только с локальным набором правил из образа: обращение к
реестру `p/...` требует сети и нарушает NFR-003. Правила лежат в
`scanner-rules/semgrep` и копируются в `/opt/semgrep-rules` при сборке
`Dockerfile.worker`.

Код 1 для Semgrep — не сбой: так инструмент сообщает о находках, если включён
`--error`. Успех определяет валидный SARIF, а не код возврата.
"""

import os
from collections.abc import Sequence
from pathlib import Path

from app.scanners.base import ScannerRun
from app.scanners.process import execute_tool

DEFAULT_RULES_DIR: Path = Path("/opt/semgrep-rules")
ALLOWED_EXIT_CODES = frozenset({0, 1})


class SemgrepAdapter:
    """Запуск Semgrep с локальными правилами и выводом в SARIF."""

    name = "semgrep"

    def __init__(self, binary: str = "semgrep", rules_dir: Path | None = None) -> None:
        self._binary = binary
        self._rules_dir = rules_dir or Path(
            os.environ.get("SEMGREP_RULES_DIR", str(DEFAULT_RULES_DIR))
        )

    def run(self, workdir: Path, output_dir: Path, timeout_sec: float) -> ScannerRun:
        """Сканирует `workdir` и возвращает результат с путём к SARIF."""
        sarif_path = output_dir / f"{self.name}.sarif"
        return execute_tool(
            name=self.name,
            command=self._command(workdir, sarif_path),
            sarif_path=sarif_path,
            timeout_sec=timeout_sec,
            allowed_exit_codes=ALLOWED_EXIT_CODES,
        )

    def _command(self, workdir: Path, sarif_path: Path) -> Sequence[str]:
        """Команда без оболочки: правила и цель — отдельные аргументы."""
        return [
            self._binary,
            "scan",
            "--config",
            str(self._rules_dir),
            "--sarif",
            "--output",
            str(sarif_path),
            # Метрики и проверка версии ходят в сеть; офлайн-прогону они не нужны.
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(workdir),
        ]
