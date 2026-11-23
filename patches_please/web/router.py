"""Страницы проекта и прогона (T-022, T-023, FR-003, FR-010, FR-018).

FR-010 требует три блока: последние прогоны, тренд находок по severity и топ-5
срабатывающих правил. Страница читает базу напрямую, без нового эндпоинта:
REST API отдаёт только запуск и статус прогона, а список для интерфейса
собирается здесь.

Страница прогона показывает сохранённые находки и фильтрует их по severity и
состоянию. Она read-only: вердикт и политику не пересчитывает, а строки
`findings` читает как есть. Фильтры проверяются до запроса: неизвестное
значение — 400 с русским сообщением, а не молчаливая пустая выдача.

Источник тренда — `scans.timings` (FR-015): у завершённого прогона там лежат
готовые счётчики по пяти уровням. Прогоны `queued`, `running` и `error` метрик
не имеют, поэтому в тренд не попадают: страница не пересчитывает находки
отдельным запросом. Топ-5 правил считается по `findings` тех же последних
десяти завершённых прогонов.

Окно — последние 10 прогонов: история проекта растёт, а тренд должен читаться
с одного экрана. Список последних прогонов показывает все статусы, но числа
находок и вердикт есть только у завершённых; у остальных в ячейках прочерк.

Доступ — по строке `project_members`, как в списке проектов (T-005). Чужой
проект отвечает 403 (FR-018), несуществующий slug — 404. Проверка прав здесь
локальная: единый помощник появится в T-025 и заменит её.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.auth.dependencies import DbSession, HtmlUser
from patches_please.metrics.service import SEVERITY_KEYS, MetricsError, RunMetrics, load_metrics
from patches_please.policy.classify import FindingState
from patches_please.projects.models import Project, ProjectMember
from patches_please.scans.findings import load_records
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus

# Шаблоны лежат внутри пакета, в patches_please/templates: отсюда это один уровень вверх.
TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Сколько прогонов показывает страница: тренд считается по тому же окну.
RECENT_RUNS_LIMIT: Final = 10
TREND_RUNS_LIMIT: Final = 10
TOP_RULES_LIMIT: Final = 5

# Подписи повторяют отчёт (T-020): шкала FR-014 одна на все экраны.
SEVERITY_LABELS: Final[dict[str, str]] = {
    "critical": "критично",
    "high": "высоко",
    "medium": "средне",
    "low": "низко",
    "info": "информационно",
}
VERDICT_LABELS: Final[dict[str, str]] = {
    "pass": "пройден",
    "fail": "не пройден",
}
STATUS_LABELS: Final[dict[str, str]] = {
    "queued": "в очереди",
    "running": "выполняется",
    "done": "завершён",
    "error": "ошибка",
}

# Состояние находки: `fixed` в таблице не хранится, поэтому и в фильтре его нет
# (delta-009). Порядок повторяет отчёт: сначала новые, затем существовавшие.
STATE_KEYS: Final[tuple[str, ...]] = (str(FindingState.NEW), str(FindingState.EXISTING))
STATE_LABELS: Final[dict[str, str]] = {
    str(FindingState.NEW): "новая",
    str(FindingState.EXISTING): "существовала",
}

# Разбор находок начинается с самого тяжёлого уровня шкалы FR-014.
SEVERITY_ORDER: Final[dict[str, int]] = {
    severity: index for index, severity in enumerate(SEVERITY_KEYS)
}

# Почему у незавершённого прогона нет таблицы: пустое состояние должно быть
# честным, а не выглядеть как «находок нет».
UNFINISHED_SCAN_MESSAGES: Final[dict[str, str]] = {
    str(ScanStatus.QUEUED): "Прогон ещё в очереди: находки появятся после завершения.",
    str(ScanStatus.RUNNING): "Прогон выполняется: находки появятся после завершения.",
    str(ScanStatus.ERROR): "Прогон завершился ошибкой: находок нет.",
}

PROJECT_NOT_FOUND_MESSAGE: Final = "Проект не найден"
PROJECT_FORBIDDEN_MESSAGE: Final = "Нет доступа к проекту"
SCAN_NOT_FOUND_MESSAGE: Final = "Прогон не найден"


@dataclass(frozen=True, slots=True)
class RunRow:
    """Строка прогона для блоков «последние прогоны» и «тренд»."""

    # Нужен для ссылки на страницу прогона из истории проекта.
    scan_id: uuid.UUID
    commit_sha: str
    date: datetime
    status: str
    verdict: str | None
    # None — прогон не завершён или метрики не сохранены: числа не выдумываем.
    counts: dict[str, int] | None

    @property
    def total(self) -> int | None:
        """Сумма находок по всем уровням; без метрик — None."""
        return None if self.counts is None else sum(self.counts.values())


@dataclass(frozen=True, slots=True)
class RuleRow:
    """Правило в топ-5: сколько раз сработало в окне тренда."""

    rule_id: str
    scanner: str
    count: int


@dataclass(frozen=True, slots=True)
class Dashboard:
    """Данные трёх блоков страницы проекта."""

    recent_runs: list[RunRow]
    trend_runs: list[RunRow]
    top_rules: list[RuleRow]


@dataclass(frozen=True, slots=True)
class ScanView:
    """Данные страницы прогона: метрики и находки после фильтров.

    `empty_message` заполнен только у незавершённого прогона: у `done` пустота
    бывает двух видов, и шаблон различает их по `findings_total`.
    """

    metrics: RunMetrics | None
    metrics_total: int | None
    findings_total: int
    findings: list[FindingRecord]
    empty_message: str | None


def find_project(session: Session, slug: str) -> Project | None:
    """Проект по slug из адреса страницы."""
    return session.scalar(select(Project).where(Project.slug == slug))


def is_project_member(session: Session, project_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """Строка членства — единственное основание видеть проект (FR-017, FR-018)."""
    statement = select(ProjectMember.project_id).where(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == user_id,
    )
    return session.scalar(statement) is not None


def find_scan(session: Session, project: Project, scan_id: uuid.UUID) -> Scan | None:
    """Прогон проекта по идентификатору из адреса.

    Условие по `project_id` обязательно: иначе участник одного проекта мог бы
    открыть прогон другого по угаданному идентификатору (FR-017, FR-018).
    """
    return session.scalar(select(Scan).where(Scan.id == scan_id, Scan.project_id == project.id))


def parse_scan_id(raw: str) -> uuid.UUID:
    """Идентификатор из адреса; битый и несуществующий одинаково дают 404."""
    try:
        return uuid.UUID(raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=SCAN_NOT_FOUND_MESSAGE,
        ) from None


def validate_filters(
    severity: str | None,
    state: str | None,
) -> tuple[str | None, str | None]:
    """Проверяет фильтры и превращает пустую строку в «без фильтра».

    Неизвестное значение — 400: страница не должна молча показывать всё или
    пустоту, если в адресе опечатка.
    """
    severity = severity or None
    state = state or None
    if severity is not None and severity not in SEVERITY_ORDER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Неизвестная важность: {_short(severity)}. "
                f"Допустимые значения: {', '.join(SEVERITY_KEYS)}"
            ),
        )
    if state is not None and state not in STATE_LABELS:
        detail = (
            "Состояние fixed не хранится в находках прогона. "
            f"Допустимые значения: {', '.join(STATE_KEYS)}"
            if state == str(FindingState.FIXED)
            else (
                f"Неизвестное состояние: {_short(state)}. "
                f"Допустимые значения: {', '.join(STATE_KEYS)}"
            )
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    return severity, state


def _short(value: str, limit: int = 40) -> str:
    """Обрезает значение из адреса перед вставкой в сообщение об ошибке."""
    return value if len(value) <= limit else f"{value[:limit]}…"


def load_scan_view(
    session: Session,
    scan: Scan,
    *,
    severity: str | None,
    state: str | None,
) -> ScanView:
    """Метрики из `scans.timings` и находки прогона после фильтров.

    Находки идут по шкале FR-014, затем по пути и строке: разбор начинается с
    самого тяжёлого места. Внутри одного места порядок задаёт `id`, чтобы выдача
    не зависела от плана запроса. Незавершённый прогон находок не читает.
    """
    if scan.status != str(ScanStatus.DONE):
        return ScanView(
            metrics=None,
            metrics_total=None,
            findings_total=0,
            findings=[],
            empty_message=UNFINISHED_SCAN_MESSAGES.get(
                scan.status,
                f"Прогон в статусе {scan.status}: находки недоступны.",
            ),
        )

    metrics = _scan_metrics(scan)
    records = load_records(session, scan.id)
    visible = [
        record
        for record in records
        if (severity is None or record.severity == severity)
        and (state is None or record.state == state)
    ]
    visible.sort(
        key=lambda record: (
            SEVERITY_ORDER.get(record.severity, len(SEVERITY_KEYS)),
            record.path,
            record.line,
            str(record.id),
        )
    )
    return ScanView(
        metrics=metrics,
        metrics_total=None if metrics is None else sum(metrics.findings_by_severity.values()),
        findings_total=len(records),
        findings=visible,
        empty_message=None,
    )


def _scan_metrics(scan: Scan) -> RunMetrics | None:
    """Метрики прогона; отсутствие или порча записи не ломает страницу."""
    try:
        return load_metrics(scan)
    except MetricsError:
        return None


def load_dashboard(session: Session, project: Project) -> Dashboard:
    """Собирает три блока страницы по сохранённым прогонам проекта.

    «Последние прогоны» — все статусы, свежие сверху. «Тренд» — только `done`
    с сохранёнными метриками, от старых к новым: так изменение видно по
    направлению таблицы. Топ-5 считается по тем же последним десяти `done`.
    """
    recent_scans = list(
        session.scalars(
            select(Scan)
            .where(Scan.project_id == project.id)
            .order_by(Scan.created_at.desc(), Scan.id)
            .limit(RECENT_RUNS_LIMIT)
        )
    )
    done_scans = list(
        session.scalars(
            select(Scan)
            .where(Scan.project_id == project.id, Scan.status == str(ScanStatus.DONE))
            .order_by(Scan.finished_at.desc().nullslast(), Scan.created_at.desc(), Scan.id)
            .limit(TREND_RUNS_LIMIT)
        )
    )

    trend_runs = [
        row for row in (_run_row(scan) for scan in reversed(done_scans)) if row.counts is not None
    ]
    return Dashboard(
        recent_runs=[_run_row(scan) for scan in recent_scans],
        trend_runs=trend_runs,
        top_rules=_top_rules(session, [scan.id for scan in done_scans]),
    )


def _run_row(scan: Scan) -> RunRow:
    """Строка прогона: дата — начало, а у непринятого в работу — время создания."""
    return RunRow(
        scan_id=scan.id,
        commit_sha=scan.commit_sha,
        date=scan.started_at or scan.created_at,
        status=scan.status,
        verdict=scan.verdict,
        counts=_severity_counts(scan),
    )


def _severity_counts(scan: Scan) -> dict[str, int] | None:
    """Счётчики из `scans.timings`; у незавершённого или испорченного прогона их нет.

    Отсутствие метрик — не ошибка страницы: прогон остаётся в списке, а ячейки
    чисел показывают прочерк. Пересчитывать находки ради строки не нужно.
    """
    if scan.status != str(ScanStatus.DONE):
        return None
    try:
        return load_metrics(scan).findings_by_severity
    except MetricsError:
        return None


def _top_rules(session: Session, scan_ids: list[uuid.UUID]) -> list[RuleRow]:
    """Топ-5 правил по числу находок в окне тренда.

    Группировка по паре «правило, сканер»: одинаковый `rule_id` у разных
    сканеров — разные правила. При равенстве порядок задаёт `rule_id`, чтобы
    выдача не зависела от плана запроса.
    """
    if not scan_ids:
        return []
    findings_count = func.count().label("findings_count")
    statement = (
        select(FindingRecord.rule_id, FindingRecord.scanner, findings_count)
        .where(FindingRecord.scan_id.in_(scan_ids))
        .group_by(FindingRecord.rule_id, FindingRecord.scanner)
        .order_by(findings_count.desc(), FindingRecord.rule_id, FindingRecord.scanner)
        .limit(TOP_RULES_LIMIT)
    )
    return [
        RuleRow(rule_id=rule_id, scanner=scanner, count=findings)
        for rule_id, scanner, findings in session.execute(statement)
    ]


html_router = APIRouter(include_in_schema=False)


@html_router.get("/projects/{slug}", summary="Страница проекта", response_class=HTMLResponse)
def project_page(request: Request, slug: str, user: HtmlUser, session: DbSession) -> HTMLResponse:
    """Последние прогоны, тренд по severity и топ-5 правил проекта.

    Несуществующий slug — 404, проект без членства текущего пользователя — 403:
    данные чужого проекта не отдаются ни в каком виде.
    """
    project = find_project(session, slug)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=PROJECT_NOT_FOUND_MESSAGE,
        )
    if not is_project_member(session, project.id, user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=PROJECT_FORBIDDEN_MESSAGE,
        )

    dashboard = load_dashboard(session, project)
    return templates.TemplateResponse(
        request,
        "project.html",
        {
            "project": project,
            "user": user,
            "dashboard": dashboard,
            "severity_keys": SEVERITY_KEYS,
            "severity_labels": SEVERITY_LABELS,
            "verdict_labels": VERDICT_LABELS,
            "status_labels": STATUS_LABELS,
        },
    )


@html_router.get(
    "/projects/{slug}/scans/{scan_id}",
    summary="Страница прогона",
    response_class=HTMLResponse,
)
def scan_page(
    request: Request,
    slug: str,
    scan_id: str,
    user: HtmlUser,
    session: DbSession,
    severity: str | None = None,
    state: str | None = None,
) -> HTMLResponse:
    """Находки прогона с фильтрами по важности и состоянию.

    Порядок проверок тот же, что на странице проекта: неизвестный slug — 404,
    чужой проект — 403 (FR-018). Прогон ищется только внутри проекта, поэтому
    идентификатор из другого проекта даёт 404, а не чужие данные.
    """
    project = find_project(session, slug)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=PROJECT_NOT_FOUND_MESSAGE,
        )
    if not is_project_member(session, project.id, user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=PROJECT_FORBIDDEN_MESSAGE,
        )

    scan = find_scan(session, project, parse_scan_id(scan_id))
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=SCAN_NOT_FOUND_MESSAGE,
        )

    severity, state = validate_filters(severity, state)
    view = load_scan_view(session, scan, severity=severity, state=state)
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "project": project,
            "scan": scan,
            "user": user,
            "view": view,
            "severity": severity,
            "state": state,
            "severity_keys": SEVERITY_KEYS,
            "severity_labels": SEVERITY_LABELS,
            "state_keys": STATE_KEYS,
            "state_labels": STATE_LABELS,
            "status_labels": STATUS_LABELS,
            "verdict_labels": VERDICT_LABELS,
        },
    )
