"""Страницы проекта, прогона и настроек (T-022…T-024, FR-003, FR-010, FR-011,
FR-014, FR-018).

FR-010 требует три блока: последние прогоны, тренд находок по severity и топ-5
срабатывающих правил. Страница читает базу напрямую, без нового эндпоинта:
REST API отдаёт только запуск и статус прогона, а список для интерфейса
собирается здесь.

Страница прогона показывает сохранённые находки и фильтрует их по severity и
состоянию. Она read-only: вердикт и политику не пересчитывает, а строки
`findings` читает как есть. Фильтры проверяются до запроса: неизвестное
значение — 400 с русским сообщением, а не молчаливая пустая выдача.

Страница настроек — одна для политики и исключений (T-024). Форма политики
пишет пороги через `upsert_policy`, форма исключения — через `create_exception`:
валидация сервисов повторяется здесь только затем, чтобы вернуть 400 и сохранить
введённые значения, а не отдать пользователю 500. Автор исключения — текущий
пользователь, а не поле формы: подставить чужое имя из браузера нельзя.
Обе формы защищены CSRF-токеном (double-submit cookie, `patches_please/web/csrf.py`).
Срок исключения вводится как `datetime-local` и трактуется как UTC — так форма
не зависит от часового пояса браузера и сервера.

Источник тренда — `scans.timings` (FR-015): у завершённого прогона там лежат
готовые счётчики по пяти уровням. Прогоны `queued`, `running` и `error` метрик
не имеют, поэтому в тренд не попадают: страница не пересчитывает находки
отдельным запросом. Топ-5 правил считается по `findings` тех же последних
десяти завершённых прогонов.

Окно — последние 10 прогонов: история проекта растёт, а тренд должен читаться
с одного экрана. Список последних прогонов показывает все статусы, но числа
находок и вердикт есть только у завершённых; у остальных в ячейках прочерк.

Доступ — по строке `project_members`, как в списке проектов (T-005). Чужой
проект отвечает 403 (FR-018), несуществующий slug — 404. Настройки меняет
только владелец: участник получает 403, посторонний — 404. Проверка прав здесь
локальная: единый помощник появится в T-025 и заменит её.
"""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Final

from fastapi import APIRouter, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.auth.dependencies import DbSession, HtmlUser
from patches_please.auth.models import User
from patches_please.metrics.service import SEVERITY_KEYS, MetricsError, RunMetrics, load_metrics
from patches_please.normalize.model import Severity
from patches_please.policy.classify import FindingState
from patches_please.policy.exceptions import (
    ExceptionValidationError,
    create_exception,
    list_exceptions,
    revoke_exception,
)
from patches_please.policy.models import ExceptionRecord
from patches_please.policy.verdict import (
    FailMode,
    PolicyError,
    ProjectPolicy,
    load_policy,
    upsert_policy,
)
from patches_please.projects.models import OWNER_ROLE, Project, ProjectMember
from patches_please.scans.findings import load_records
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import ScanStatus
from patches_please.tokens.router import project_role, require_project_owner
from patches_please.web.csrf import (
    CSRF_FIELD_NAME,
    require_csrf,
    set_csrf_cookie,
    token_from_request,
)

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
EXCEPTION_NOT_FOUND_MESSAGE: Final = "Исключение не найдено"

# Подписи режима деградации и состояния исключения: словарь один на страницу.
FAIL_MODE_LABELS: Final[dict[str, str]] = {
    "open": "fail-open: неполная проверка не блокирует",
    "closed": "fail-closed: неполная проверка блокирует",
}
EXCEPTION_STATUS_LABELS: Final[dict[str, str]] = {
    "active": "действует",
    "expired": "истёк",
    "revoked": "отозван",
}

# Тексты ошибок формы: поле названо, чтобы его было видно рядом с вводом.
TIMEOUT_INVALID_MESSAGE: Final = "Таймаут сканеров должен быть целым положительным числом"
FAIL_MODE_INVALID_MESSAGE: Final = "Режим деградации должен быть open или closed"
EXPIRY_REQUIRED_MESSAGE: Final = "Поле «срок действия» обязательно"
EXPIRY_INVALID_MESSAGE: Final = "Поле «срок действия»: укажите дату и время"


class SettingsFormError(ValueError):
    """Значение формы настроек не прошло проверку; текст показывается пользователю."""


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


@dataclass(frozen=True, slots=True)
class PolicyFormValues:
    """Значения формы политики; строки возвращаются в форму как есть.

    Таймаут хранится строкой: при ошибке пользователь видит именно то, что ввёл,
    а не приведённое число. По умолчанию значения берутся из действующей политики.
    """

    block_severities: frozenset[str]
    fail_mode: str
    scanner_timeout_sec: str

    @classmethod
    def from_policy(cls, policy: ProjectPolicy) -> "PolicyFormValues":
        """Показывает действующую политику проекта, включая умолчание."""
        return cls(
            block_severities=frozenset(str(severity) for severity in policy.block_severities),
            fail_mode=str(policy.fail_mode),
            scanner_timeout_sec=str(policy.scanner_timeout_sec),
        )


@dataclass(frozen=True, slots=True)
class ExceptionFormValues:
    """Значения формы исключения: после ошибки возвращаются без потерь."""

    rule_id: str = ""
    path_glob: str = ""
    reason: str = ""
    # `datetime-local` присылает строку без пояса; разбирается как UTC.
    expires_at: str = ""


@dataclass(frozen=True, slots=True)
class ExceptionView:
    """Строка таблицы исключений: запись, автор и вычисленное состояние."""

    id: uuid.UUID
    rule_id: str
    path_glob: str
    reason: str
    author_email: str
    expires_at: datetime
    status: str


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


def _require_owned_project(session: Session, slug: str, user: User) -> Project:
    """Проект для страницы настроек: неизвестный slug — 404, права — по роли.

    `require_project_owner` даёт 403 участнику без роли `owner` и 404 постороннему:
    наличие чужого проекта не раскрывается.
    """
    project = find_project(session, slug)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=PROJECT_NOT_FOUND_MESSAGE,
        )
    require_project_owner(session, project.id, user)
    return project


def exception_status(record: ExceptionRecord, moment: datetime) -> str:
    """Состояние исключения для интерфейса: отозвано, истекло или действует."""
    if record.revoked_at is not None:
        return "revoked"
    if record.expires_at <= moment:
        return "expired"
    return "active"


def _author_emails(session: Session, records: Iterable[ExceptionRecord]) -> dict[uuid.UUID, str]:
    """Почты авторов одним запросом: в таблице нужен автор, а не только id."""
    author_ids = {record.author_id for record in records}
    if not author_ids:
        return {}
    statement = select(User.id, User.email).where(User.id.in_(author_ids))
    return {user_id: email for user_id, email in session.execute(statement)}


def load_exception_views(
    session: Session,
    project_id: uuid.UUID,
    *,
    now: datetime | None = None,
) -> list[ExceptionView]:
    """Исключения проекта для таблицы: свежие сверху, с автором и состоянием."""
    moment = now or datetime.now(UTC)
    records = list_exceptions(session, project_id)
    emails = _author_emails(session, records)
    return [
        ExceptionView(
            id=record.id,
            rule_id=record.rule_id,
            path_glob=record.path_glob,
            reason=record.reason,
            author_email=emails.get(record.author_id, "—"),
            expires_at=record.expires_at,
            status=exception_status(record, moment),
        )
        for record in records
    ]


def parse_policy_form(
    raw_severities: Iterable[str],
    raw_fail_mode: str,
    raw_timeout: str,
) -> tuple[frozenset[Severity], FailMode, int]:
    """Проверяет форму политики; ошибка — `SettingsFormError` с русским текстом.

    Набор уровней может быть пустым: политика, которая ничего не блокирует.
    Неизвестный уровень, чужой режим деградации и неположительный таймаут
    отклоняются до записи, поэтому строка `policies` не меняется.
    """
    severities = tuple(raw_severities)
    unknown = sorted({value for value in severities if value not in SEVERITY_ORDER})
    if unknown:
        raise SettingsFormError(
            f"Неизвестная важность: {', '.join(unknown)}. "
            f"Допустимые значения: {', '.join(SEVERITY_KEYS)}"
        )
    try:
        fail_mode = FailMode(raw_fail_mode)
    except ValueError:
        raise SettingsFormError(FAIL_MODE_INVALID_MESSAGE) from None
    try:
        timeout = int(raw_timeout.strip())
    except ValueError:
        raise SettingsFormError(TIMEOUT_INVALID_MESSAGE) from None
    if timeout <= 0:
        raise SettingsFormError(TIMEOUT_INVALID_MESSAGE)
    return frozenset(Severity(value) for value in severities), fail_mode, timeout


def parse_expires_at(raw: str) -> datetime:
    """Срок из `datetime-local`: пустое значение и мусор — ошибка поля.

    Время без часового пояса трактуется как UTC: форма подписана «(UTC)»,
    поэтому результат не зависит от настроек браузера и сервера.
    """
    value = raw.strip()
    if not value:
        raise ExceptionValidationError(EXPIRY_REQUIRED_MESSAGE)
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise ExceptionValidationError(EXPIRY_INVALID_MESSAGE) from None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def parse_exception_id(raw: str) -> uuid.UUID:
    """Идентификатор исключения из адреса; битый — 404, как у прогона."""
    try:
        return uuid.UUID(raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=EXCEPTION_NOT_FOUND_MESSAGE,
        ) from None


def find_project_exception(
    session: Session,
    project: Project,
    exception_id: uuid.UUID,
) -> ExceptionRecord:
    """Исключение внутри проекта: чужое или несуществующее — 404.

    Условие по проекту обязательно: иначе владелец одного проекта отозвал бы
    исключение другого по угаданному идентификатору (FR-017, FR-018).
    """
    record = session.get(ExceptionRecord, exception_id)
    if record is None or record.project_id != project.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=EXCEPTION_NOT_FOUND_MESSAGE,
        )
    return record


def render_settings(
    request: Request,
    session: Session,
    project: Project,
    user: User,
    *,
    policy_values: PolicyFormValues | None = None,
    exception_values: ExceptionFormValues | None = None,
    policy_error: str | None = None,
    exception_error: str | None = None,
    status_code: int = status.HTTP_200_OK,
) -> HTMLResponse:
    """Страница настроек: политика и исключения, форма ошибки и CSRF-cookie.

    Cookie CSRF ставится тем же ответом, что и страница: скрытое поле формы
    и cookie приходят из одного рендера и совпадают.
    """
    policy = load_policy(session, project.id)
    token = token_from_request(request)
    response = templates.TemplateResponse(
        request,
        "settings.html",
        {
            "project": project,
            "user": user,
            "policy_values": policy_values or PolicyFormValues.from_policy(policy),
            "exception_values": exception_values or ExceptionFormValues(),
            "policy_error": policy_error,
            "exception_error": exception_error,
            "exception_views": load_exception_views(session, project.id),
            "severity_keys": SEVERITY_KEYS,
            "severity_labels": SEVERITY_LABELS,
            "fail_mode_labels": FAIL_MODE_LABELS,
            "exception_status_labels": EXCEPTION_STATUS_LABELS,
            "csrf_field": CSRF_FIELD_NAME,
            "csrf_token": token,
        },
        status_code=status_code,
    )
    set_csrf_cookie(response, token)
    return response


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
            "is_owner": project_role(session, project.id, user.id) == OWNER_ROLE,
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


@html_router.get(
    "/projects/{slug}/settings",
    summary="Настройки проекта",
    response_class=HTMLResponse,
)
def settings_page(request: Request, slug: str, user: HtmlUser, session: DbSession) -> HTMLResponse:
    """Политика и исключения проекта: видит и меняет только владелец.

    Неизвестный slug — 404, участник без роли `owner` — 403, посторонний — 404.
    Политика читается через `load_policy`: без строки показывается умолчание
    (`critical` и `high`, fail-open, 300 секунд), а не пустая форма.
    """
    project = _require_owned_project(session, slug, user)
    return render_settings(request, session, project, user)


@html_router.post(
    "/projects/{slug}/settings/policy",
    summary="Сохранение политики из формы",
    response_class=HTMLResponse,
)
def policy_submit(
    request: Request,
    slug: str,
    user: HtmlUser,
    session: DbSession,
    csrf_token: Annotated[str, Form()] = "",
    block_severities: Annotated[list[str] | None, Form()] = None,
    fail_mode: Annotated[str, Form()] = "",
    scanner_timeout_sec: Annotated[str, Form()] = "",
) -> Response:
    """Проверяет и сохраняет пороги, режим деградации и таймаут.

    Ошибка — 400 с той же страницей: введённые значения остаются в форме,
    а строка `policies` не меняется. Успех — 303 на страницу настроек, чтобы
    обновление страницы не сохраняло политику повторно.
    """
    project = _require_owned_project(session, slug, user)
    require_csrf(request, csrf_token)
    submitted = PolicyFormValues(
        block_severities=frozenset(block_severities or []),
        fail_mode=fail_mode,
        scanner_timeout_sec=scanner_timeout_sec,
    )
    try:
        severities, mode, timeout = parse_policy_form(
            submitted.block_severities,
            submitted.fail_mode,
            submitted.scanner_timeout_sec,
        )
        upsert_policy(
            session,
            project.id,
            block_severities=severities,
            fail_mode=mode,
            scanner_timeout_sec=timeout,
        )
    except (SettingsFormError, PolicyError) as error:
        return render_settings(
            request,
            session,
            project,
            user,
            policy_values=submitted,
            policy_error=str(error),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/projects/{project.slug}/settings",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@html_router.post(
    "/projects/{slug}/settings/exceptions",
    summary="Создание исключения из формы",
    response_class=HTMLResponse,
)
def exception_submit(
    request: Request,
    slug: str,
    user: HtmlUser,
    session: DbSession,
    csrf_token: Annotated[str, Form()] = "",
    rule_id: Annotated[str, Form()] = "",
    path_glob: Annotated[str, Form()] = "",
    reason: Annotated[str, Form()] = "",
    expires_at: Annotated[str, Form()] = "",
) -> Response:
    """Создаёт исключение с автором-текущим пользователем и сроком в UTC.

    Обязательные поля проверяет `create_exception`: без причины ответ 400,
    поле названо, строка в `exceptions` не появляется (FR-011, S-005).
    """
    project = _require_owned_project(session, slug, user)
    require_csrf(request, csrf_token)
    submitted = ExceptionFormValues(
        rule_id=rule_id,
        path_glob=path_glob,
        reason=reason,
        expires_at=expires_at,
    )
    try:
        create_exception(
            session,
            project_id=project.id,
            rule_id=rule_id,
            path_glob=path_glob,
            reason=reason,
            author_id=user.id,
            expires_at=parse_expires_at(expires_at),
        )
    except ExceptionValidationError as error:
        return render_settings(
            request,
            session,
            project,
            user,
            exception_values=submitted,
            exception_error=str(error),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/projects/{project.slug}/settings",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@html_router.post(
    "/projects/{slug}/settings/exceptions/{exception_id}/revoke",
    summary="Отзыв исключения из формы",
    response_class=HTMLResponse,
)
def exception_revoke(
    request: Request,
    slug: str,
    exception_id: str,
    user: HtmlUser,
    session: DbSession,
    csrf_token: Annotated[str, Form()] = "",
) -> Response:
    """Отзывает исключение проекта: после отзыва оно не снимает находку (FR-012).

    Отозванное исключение остаётся в таблице с состоянием «отозван»: история действий
    не пропадает. Чужое или неизвестное исключение — 404 (FR-018).
    """
    project = _require_owned_project(session, slug, user)
    require_csrf(request, csrf_token)
    record = find_project_exception(session, project, parse_exception_id(exception_id))
    try:
        revoke_exception(session, record.id, actor=user.id)
    except ExceptionValidationError as error:
        return render_settings(
            request,
            session,
            project,
            user,
            exception_error=str(error),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=f"/projects/{project.slug}/settings",
        status_code=status.HTTP_303_SEE_OTHER,
    )
