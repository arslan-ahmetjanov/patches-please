"""Адаптер Gitleaks: поиск секретов в рабочем каталоге (T-013, FR-002, FR-030).

Gitleaks сканирует каталог командой `dir`, а не историю git: worker получает
клон без гарантированной истории (`--depth 1`), а проверяться должен код
текущего коммита. Секреты в отчёт попадают в замаскированном виде (`--redact`):
полное маскирование по всем выходам — T-021, но содержимое не должно утекать
уже на этапе сканера.

Код 1 означает и находки, и ошибку, поэтому успех определяется валидным SARIF,
а не кодом возврата.
"""

from collections.abc import Sequence
from pathlib import Path

from app.scanners.base import ScannerRun
from app.scanners.process import execute_tool

ALLOWED_EXIT_CODES = frozenset({0, 1})


class GitleaksAdapter:
    """Запуск Gitleaks по каталогу с отчётом в SARIF."""

    name = "gitleaks"

    def __init__(self, binary: str = "gitleaks") -> None:
        self._binary = binary

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
        """Команда без оболочки: каталог и отчёт — отдельные аргументы."""
        return [
            self._binary,
            "dir",
            str(workdir),
            "--report-format",
            "sarif",
            "--report-path",
            str(sarif_path),
            # Баннер и цветной вывод не нужны: stdout всё равно отбрасывается.
            "--no-banner",
            "--redact",
        ]
