"""Офлайн-проверка трёх адаптеров внутри образа worker (T-013, FR-030).

Модуль запускает Semgrep, Gitleaks и Trivy на переданном каталоге и печатает
сводку в JSON: статус, версия инструмента, путь к SARIF и число нормализованных
находок. Содержимое находок не выводится — только счётчики: вывод проверки
попадает в терминал и журнал CI.

Проверка считается успешной, если все три адаптера вернули `ok`, SARIF каждого
разобран нормализатором (FR-029), а с `--require-findings` — ещё и дал хотя бы
одну находку. Именно так подтверждается NFR-003: образ собран с правилами и
базой, прогон с `--network none` не обращается в интернет.
"""

import argparse
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from app.normalize.sarif import NormalizationError, normalize_run
from app.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.runner import DEFAULT_SCANNER_TIMEOUT_SEC, run_scanners
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.trivy import TrivyAdapter

SARIF_DIR_NAME: Final = "artifacts"
EXIT_OK: Final = 0
EXIT_FAILED: Final = 1


def default_adapters() -> list[ScannerAdapter]:
    """Три реальных адаптера в порядке отчёта: SAST, секреты, зависимости."""
    return [SemgrepAdapter(), GitleaksAdapter(), TrivyAdapter()]


def scan_offline(
    workdir: Path,
    output_dir: Path,
    timeout_sec: float = DEFAULT_SCANNER_TIMEOUT_SEC,
    *,
    require_findings: bool = False,
) -> tuple[bool, list[dict[str, Any]]]:
    """Запускает адаптеры и возвращает признак успеха и сводку по каждому.

    Сводка содержит только метаданные: имя, статус, версию, путь к SARIF,
    причину отказа и число находок. Сообщения находок и фрагменты кода не
    попадают ни в сводку, ни в лог (NFR-004).
    """
    runs = run_scanners(default_adapters(), workdir, output_dir, timeout_sec)
    summary: list[dict[str, Any]] = []
    success = True
    for run in runs:
        item = _run_summary(run, workdir, require_findings)
        # `pop` вызывается всегда: короткое замыкание оставило бы служебный
        # признак в JSON после первого отказа.
        item_ok = bool(item.pop("_ok"))
        success = success and item_ok
        summary.append(item)
    return success, summary


def _run_summary(run: ScannerRun, workdir: Path, require_findings: bool) -> dict[str, Any]:
    """Сводка одного запуска; `_ok` — служебный признак, наружу не выводится."""
    item: dict[str, Any] = {
        "scanner": run.scanner,
        "status": str(run.status),
        "tool_version": run.tool_version,
        "sarif": str(run.sarif_path) if run.sarif_path is not None else None,
        "error": run.error,
        "findings": None,
        "_ok": run.status is ScannerStatus.OK,
    }
    if run.status is not ScannerStatus.OK:
        return item
    try:
        count = len(normalize_run(run, workdir))
    except NormalizationError as exc:
        item["_ok"] = False
        item["error"] = str(exc)
        return item
    item["findings"] = count
    if require_findings and count == 0:
        item["_ok"] = False
        item["error"] = "Сканер не нашёл ни одной находки"
    return item


def main(argv: Sequence[str] | None = None) -> int:
    """Точка входа `python -m app.scanners.offline` внутри образа worker."""
    parser = argparse.ArgumentParser(
        prog="python -m app.scanners.offline",
        description="Офлайн-прогон Semgrep, Gitleaks и Trivy с проверкой SARIF.",
    )
    parser.add_argument("--workdir", type=Path, required=True, help="каталог для сканирования")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp") / SARIF_DIR_NAME,
        help="каталог для SARIF (по умолчанию /tmp/artifacts)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(DEFAULT_SCANNER_TIMEOUT_SEC),
        help="общий таймаут сканеров, секунды",
    )
    parser.add_argument(
        "--require-findings",
        action="store_true",
        help="считать прогон неуспешным, если сканер не дал находок",
    )
    args = parser.parse_args(argv)
    if not args.workdir.is_dir():
        parser.error(f"каталог для сканирования не найден: {args.workdir}")
    success, summary = scan_offline(
        args.workdir,
        args.output,
        args.timeout,
        require_findings=args.require_findings,
    )
    print(json.dumps({"ok": success, "runs": summary}, ensure_ascii=False, indent=2))
    return EXIT_OK if success else EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
