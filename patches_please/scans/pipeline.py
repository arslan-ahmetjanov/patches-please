"""Оркестрация прогона в воркере за один проход (T-038, FR-002, FR-005, FR-019).

Обработчик очереди переводит прогон `queued → running` и передаёт его сюда.
Дальше шаги идут строго по порядку:

1. проект и адрес репозитория: без `repo_url` проверять нечего — прогон
   завершается `error` с причиной, а не «чистым» вердиктом;
2. клон нужного коммита во временный каталог (`clone_repository`);
3. три сканера параллельно с таймаутом из политики проекта (T-011, FR-002);
4. нормализация SARIF и классификация `new`/`existing` по базе сравнения
   (T-012, T-014);
5. запись находок, действующие исключения, `done`, метрики и вердикт с учётом
   деградации проверок (T-016, T-019);
6. два файла отчёта — JSON и HTML — в каталог `REPORTS_DIR` (T-020, FR-008).

Пометка `degraded` живёт только в памяти и логе: таблицы `scanner_runs` нет,
в отчёт она попадает по итогам запусков, которые конвейер передаёт дальше.
Вердикт остаётся ровно `pass`/`fail` (FR-004), режим отказа решает, блокирует
ли неполная проверка (FR-013).

Сбой записи отчёта не меняет исход прогона: находки, метрики и вердикт уже
сохранены, файлы можно пересобрать повторной обработкой. Поэтому ошибка ввода-
вывода только логируется, а прогон остаётся `done`.

Провайдер CI на шаги не влияет: `scans.provider` только хранится, поэтому
GitHub Actions и GitLab CI идут одним путём (FR-019). Адрес репозитория и вывод
git не попадают ни в лог, ни в причину ошибки: в них могут быть учётные данные
(NFR-004).

Сбой клона и пустой `repo_url` — это `error`, а не вердикт: отказ конфигурации
не должен выглядеть блокировкой по находкам. Прочие исключения пробрасываются
обработчику сбоя задачи RQ (`handle_scan_failure`, FR-027).
"""

import logging
import os
import shutil
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import replace
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired, run
from typing import Final

from sqlalchemy.orm import Session

from patches_please.db import SessionLocal
from patches_please.metrics.service import RunMetrics, save_metrics
from patches_please.normalize.model import Finding
from patches_please.normalize.sarif import NormalizationError, normalize_run
from patches_please.policy.baseline import resolve_base
from patches_please.policy.classify import classify
from patches_please.policy.degraded import degraded_checks
from patches_please.policy.verdict import apply_exceptions, load_policy, save_verdict
from patches_please.projects.models import Project
from patches_please.reports.artifacts import save_reports
from patches_please.scanners.base import ScannerAdapter, ScannerRun, ScannerStatus
from patches_please.scanners.offline import default_adapters
from patches_please.scanners.runner import run_scanners
from patches_please.scans.findings import load_records, save_findings
from patches_please.scans.models import Scan
from patches_please.scans.service import ScanTransitionError, mark_done, mark_error

logger = logging.getLogger(__name__)

# Воркер открывает сессию сам; тесты подставляют `nullcontext` с тестовой сессией.
SessionScope = Callable[[], AbstractContextManager[Session]]
# Обработчик прогона: очередь передаёт его как зависимость, тесты — свой.
ScanPipeline = Callable[..., None]

WORKSPACE_PREFIX: Final = "patches-please-scan-"
REPO_DIR_NAME: Final = "repo"
ARTIFACTS_DIR_NAME: Final = "artifacts"
CLONE_TIMEOUT_SEC: Final = 120
MISSING_REPO_REASON: Final = "У проекта не задан адрес репозитория"
CLONE_FAILED_TEMPLATE: Final = "Не удалось получить код коммита: {reason}"
CLONE_EXIT_TEMPLATE: Final = "git {command} завершился с кодом {code}"
CLONE_TIMEOUT_REASON: Final = "превышен таймаут git ({timeout} с)"
CLONE_UNAVAILABLE_REASON: Final = "git не установлен в образе worker"
NORMALIZATION_REASON_TEMPLATE: Final = "SARIF не разобран: {reason}"


class CloneError(Exception):
    """Код коммита не удалось получить: причина без адреса репозитория и вывода git."""


def clone_repository(repo_url: str, commit_sha: str, workdir: Path) -> None:
    """Клонирует репозиторий и переключает его на нужный коммит.

    Сначала пробуем забрать ровно нужный коммит (`--depth 1`), затем — все
    ссылки: провайдеры по-разному разрешают выборку по SHA. Команды идут
    списком аргументов, без `shell=True` (NFR-004); адрес репозитория не
    попадает ни в лог, ни в причину ошибки — в нём могут быть учётные данные.
    """
    if not repo_url.strip():
        raise CloneError(CLONE_FAILED_TEMPLATE.format(reason="пустой адрес репозитория"))
    if not commit_sha.strip():
        raise CloneError(CLONE_FAILED_TEMPLATE.format(reason="пустой идентификатор коммита"))
    workdir.mkdir(parents=True, exist_ok=False)
    # Без интерактивного запроса пароля: в CI его некому ввести.
    # Клон идёт по адресу из `repo_url`; локальный смонтированный каталог
    # должен принадлежать пользователю контейнера (uid 10001).
    environment = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    _git(["init", "--quiet", "."], workdir, environment)
    _git(["remote", "add", "origin", repo_url], workdir, environment)
    try:
        _git(["fetch", "--depth", "1", "origin", commit_sha], workdir, environment)
        target = "FETCH_HEAD"
    except CloneError as exc:
        # Провайдер не отдал одиночный коммит: забираем все ссылки и ищем SHA.
        logger.info("выборка коммита не удалась, пробуем полную: %s", exc)
        _git(["fetch", "origin"], workdir, environment)
        target = commit_sha
    _git(["checkout", "--detach", target], workdir, environment)


def execute_scan(
    scan_id: str,
    *,
    session_scope: SessionScope = SessionLocal,
    adapters: Sequence[ScannerAdapter] | None = None,
    clone: Callable[[str, str, Path], None] = clone_repository,
    workspace: Path | None = None,
    reports_dir: Path | None = None,
) -> None:
    """Проводит прогон от `running` до `done` с находками, метриками и отчётами.

    `adapters`, `clone`, `workspace` и `reports_dir` — точки подмены для тестов:
    боевой вызов берёт три адаптера, git, временный каталог и `REPORTS_DIR`.
    Неизвестный прогон и повторная доставка не считаются ошибкой задачи:
    менять уже нечего.
    """
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        logger.error("некорректный идентификатор прогона", extra={"scan_id": scan_id})
        return
    owns_workspace = workspace is None
    root = Path(tempfile.mkdtemp(prefix=WORKSPACE_PREFIX)) if workspace is None else workspace
    try:
        with session_scope() as session:
            scan = session.get(Scan, scan_uuid)
            if scan is None:
                logger.warning("прогон не найден", extra={"scan_id": scan_id})
                return
            try:
                _run_steps(session, scan, root, adapters, clone, reports_dir)
            except ScanTransitionError as exc:
                logger.warning("статус прогона не изменён: %s", exc, extra={"scan_id": scan_id})
    finally:
        # Клон нужен только на время прогона: каталог удаляется вместе с SARIF.
        if owns_workspace:
            shutil.rmtree(root, ignore_errors=True)


def _run_steps(
    session: Session,
    scan: Scan,
    root: Path,
    adapters: Sequence[ScannerAdapter] | None,
    clone: Callable[[str, str, Path], None],
    reports_dir: Path | None,
) -> None:
    """Шаги прогона по порядку; сессию и временный каталог задаёт вызывающий."""
    project = session.get(Project, scan.project_id)
    repo_url = project.repo_url if project is not None else None
    if project is None or not repo_url:
        logger.warning("у проекта нет адреса репозитория", extra={"scan_id": str(scan.id)})
        mark_error(session, scan, MISSING_REPO_REASON)
        return

    policy = load_policy(session, scan.project_id)
    checkout = root / REPO_DIR_NAME
    artifacts = root / ARTIFACTS_DIR_NAME
    try:
        clone(repo_url, scan.commit_sha, checkout)
    except CloneError as exc:
        # Причина уже очищена от адреса и вывода git (NFR-004).
        logger.warning("клон не удался: %s", exc, extra={"scan_id": str(scan.id)})
        mark_error(session, scan, str(exc))
        return

    runs = run_scanners(
        adapters if adapters is not None else default_adapters(),
        checkout,
        artifacts,
        policy.scanner_timeout_sec,
    )
    findings: list[Finding] = []
    collected: list[ScannerRun] = []
    for scanner_run in runs:
        normalized, collected_run = _normalize(scanner_run, checkout)
        findings.extend(normalized)
        collected.append(collected_run)

    for check in degraded_checks(collected):
        # Причина уже без вывода инструмента и текста исключения (NFR-004).
        logger.warning(
            "проверка деградировала: %s, %s",
            check.scanner,
            check.error,
            extra={"scan_id": str(scan.id), "scanner": check.scanner},
        )

    base = resolve_base(session, scan.project_id, current_scan_id=scan.id)
    classification = classify(findings, base.fingerprints)
    save_findings(session, scan, classification)
    apply_exceptions(session, scan)
    mark_done(session, scan)
    metrics = save_metrics(session, scan)
    verdict = save_verdict(session, scan, collected)
    _save_reports(session, scan, project, metrics, collected, reports_dir)
    logger.info(
        "прогон завершён: %s, находок %s, деградировавших проверок %s",
        verdict,
        len(classification.findings),
        len(degraded_checks(collected)),
        extra={"scan_id": str(scan.id)},
    )


def _save_reports(
    session: Session,
    scan: Scan,
    project: Project,
    metrics: RunMetrics,
    runs: Sequence[ScannerRun],
    reports_dir: Path | None,
) -> None:
    """Пишет JSON- и HTML-отчёт рядом с сохранённым вердиктом (FR-008).

    Политика читается здесь, а не берётся из начала прогона: пороги для пометки
    `blocking` те же, что у только что вынесенного вердикта. Файлы — следствие
    уже записанных данных, поэтому сбой записи не отменяет прогон: в лог уходит
    предупреждение без содержимого находок (NFR-004), а прогон остаётся `done`
    с вердиктом.
    """
    try:
        artifacts = save_reports(
            scan,
            project,
            load_records(session, scan.id),
            metrics,
            runs,
            load_policy(session, scan.project_id).block_severities,
            directory=reports_dir,
        )
    except OSError as exc:
        logger.warning("отчёты не записаны: %s", exc, extra={"scan_id": str(scan.id)})
        return
    logger.info(
        "отчёты записаны: %s, %s",
        artifacts.json_path.name,
        artifacts.html_path.name,
        extra={"scan_id": str(scan.id)},
    )


def _normalize(run: ScannerRun, workdir: Path) -> tuple[list[Finding], ScannerRun]:
    """Находки запуска и его итоговый результат.

    Битый SARIF не роняет прогон: проверка помечается `failed` и попадает в
    деградацию, как упавший сканер (FR-013). Успешный результат возвращается
    без изменений.
    """
    if run.status is not ScannerStatus.OK:
        return [], run
    try:
        return normalize_run(run, workdir), run
    except NormalizationError as exc:
        logger.warning(
            "SARIF не разобран: %s, %s", run.scanner, exc, extra={"scanner": run.scanner}
        )
        return [], replace(
            run,
            status=ScannerStatus.FAILED,
            sarif_path=None,
            error=NORMALIZATION_REASON_TEMPLATE.format(reason=str(exc)),
        )


def _git(args: Sequence[str], cwd: Path, environment: Mapping[str, str]) -> None:
    """Запускает git списком аргументов и переводит сбой в `CloneError`.

    Текст ошибки собирается из имени команды и кода возврата: stderr git может
    содержать адрес репозитория с токеном (NFR-004).
    """
    try:
        run(
            ["git", *args],
            cwd=cwd,
            env=dict(environment),
            capture_output=True,
            text=True,
            timeout=CLONE_TIMEOUT_SEC,
            check=True,
        )
    except FileNotFoundError as exc:
        raise CloneError(CLONE_FAILED_TEMPLATE.format(reason=CLONE_UNAVAILABLE_REASON)) from exc
    except TimeoutExpired as exc:
        raise CloneError(
            CLONE_FAILED_TEMPLATE.format(
                reason=CLONE_TIMEOUT_REASON.format(timeout=CLONE_TIMEOUT_SEC)
            )
        ) from exc
    except CalledProcessError as exc:
        raise CloneError(
            CLONE_FAILED_TEMPLATE.format(
                reason=CLONE_EXIT_TEMPLATE.format(command=args[0], code=exc.returncode)
            )
        ) from exc
