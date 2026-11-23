"""Страница проекта: последние прогоны, тренд и топ правил (T-022, FR-010).

FR-010 требует три блока: последние прогоны, тренд находок по severity и топ-5
срабатывающих правил. Страница читает базу напрямую, без нового эндпоинта:
REST API отдаёт только запуск и статус прогона, а список для интерфейса
собирается здесь.

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
from patches_please.metrics.service import SEVERITY_KEYS, MetricsError, load_metrics
from patches_please.projects.models import Project, ProjectMember
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
    "error": "ошибка",
}

PROJECT_NOT_FOUND_MESSAGE: Final = "Проект не найден"
PROJECT_FORBIDDEN_MESSAGE: Final = "Нет доступа к проекту"


@dataclass(frozen=True, slots=True)
class RunRow:
    """Строка прогона для блоков «последние прогоны» и «тренд»."""

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
