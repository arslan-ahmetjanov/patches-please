"""Адаптер Trivy: уязвимые зависимости файловой системы (T-013, FR-002, FR-030).

Trivy сканирует `workdir` как файловую систему (`fs`), а не образ: в V1
проверяется исходный код репозитория, и манифесты зависимостей (`requirements.txt`,
`package-lock.json` и другие) лежат в нём. База уязвимостей запечена в образ при
сборке (`--download-db-only`), а прогон идёт с `--skip-db-update` и без сети
(NFR-003).

Проверяются только уязвимости (`--scanners vuln`): секреты ищет Gitleaks,
а конфигурации инфраструктуры в FR-002 не входят. Код 0 — норма для Trivy
независимо от числа находок, поэтому любой другой код означает сбой.
"""

import os
from collections.abc import Sequence
from pathlib import Path

from app.scanners.base import ScannerRun
from app.scanners.process import execute_tool

DEFAULT_CACHE_DIR: Path = Path("/opt/trivy-cache")
ALLOWED_EXIT_CODES = frozenset({0})


class TrivyAdapter:
    """Запуск Trivy по файловой системе с офлайн-базой уязвимостей."""

    name = "trivy"

    def __init__(self, binary: str = "trivy", cache_dir: Path | None = None) -> None:
        self._binary = binary
        self._cache_dir = cache_dir or Path(
            os.environ.get("TRIVY_CACHE_DIR", str(DEFAULT_CACHE_DIR))
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
        """Команда без оболочки: цель, база и отчёт — отдельные аргументы."""
        return [
            self._binary,
            "fs",
            str(workdir),
            "--format",
            "sarif",
            "--output",
            str(sarif_path),
            "--scanners",
            "vuln",
            "--cache-dir",
            str(self._cache_dir),
            # База скачана при сборке образа: прогон не ходит в сеть (NFR-003).
            "--skip-db-update",
            "--skip-java-db-update",
            "--quiet",
        ]
