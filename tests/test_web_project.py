"""Страница проекта: прогоны, тренд и топ правил (T-022, FR-010, CON-004).

Сценарий S-006 проверяется на тестовых данных: демо-репозитория (T-032) и
живого прогона пока нет, поэтому завершённые прогоны собираются строками
`scans`, `findings` и `scans.timings` в тестовой базе — так же, как их
оставляет конвейер T-038.

Быстрые проверки не нужны: страница целиком строится по базе, поэтому все
тесты интеграционные. Доступ проверяется по `project_members`: чужой проект
отвечает 403 и не отдаёт ни названия, ни коммитов, ни правил.
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import AppClient
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.auth.models import User
from patches_please.main import app
from patches_please.metrics.service import SEVERITY_KEYS
from patches_please.scans.models import FindingRecord, Scan

PASSWORD = "пароль-123"
BASE_TIME = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)

# Заголовки блоков: по ним тесты находят нужную секцию в готовой странице.
RECENT_HEADING = "Последние досмотры"
TREND_HEADING = "Тренд находок по важности"
TOP_HEADING = "Топ-5 правил"


def _create_user(session: Session, email: str) -> User:
    """Учётная запись для входа: регистрации нет, пользователя заводит тест."""
    return service.create_user(session, email, PASSWORD)


def _login(client: AppClient, email: str) -> None:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text


def _create_project(client: AppClient, name: str, slug: str) -> uuid.UUID:
    response = client.post("/api/v1/projects", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _finding(
    scan: Scan,
    index: int,
    rule_id: str,
    scanner: str,
    severity: str,
) -> FindingRecord:
    """Находка с уникальным fingerprint: пара (прогон, правило, индекс) уникальна."""
    return FindingRecord(
        scan_id=scan.id,
        fingerprint=hashlib.sha256(f"{scan.id}:{rule_id}:{index}".encode()).hexdigest(),
        scanner=scanner,
        rule_id=rule_id,
        finding_type="sast",
        severity=severity,
        path="src/app.py",
        line=index + 1,
        message=f"Находка {rule_id}",
        state="new",
        excluded=False,
    )


def _add_scan(
    session: Session,
    project_id: uuid.UUID,
    *,
    commit_sha: str,
    at: datetime,
    status: str = "done",
    verdict: str = "pass",
    counts: dict[str, int] | None = None,
    findings: list[tuple[str, str, str]] | None = None,
) -> Scan:
    """Прогон в нужном статусе; метрики пишутся только для `done`.

    `at` — время завершения (или создания для незавершённого прогона). Время
    создания и начала сдвинуто назад, чтобы порядок в истории был однозначен
    и не зависел от часов машины.
    """
    started_at = None
    finished_at = None
    timings = None
    if status in ("done", "error"):
        started_at = at - timedelta(minutes=1)
        finished_at = at
    if status == "done" and counts is not None:
        timings = {
            "duration_sec": 60.0,
            "findings_by_severity": {
                severity: counts.get(severity, 0) for severity in SEVERITY_KEYS
            },
            "new": sum(counts.values()),
            "fixed": 0,
            "excluded_ratio": 0.0,
        }

    scan = Scan(
        project_id=project_id,
        commit_sha=commit_sha,
        ref="refs/heads/main",
        provider="github",
        status=status,
        verdict=verdict if status == "done" else None,
        error="Сканер упал" if status == "error" else None,
        timings=timings,
        created_at=at - timedelta(minutes=2),
        started_at=started_at,
        finished_at=finished_at,
    )
    session.add(scan)
    session.flush()
    for index, (rule_id, scanner, severity) in enumerate(findings or []):
        session.add(_finding(scan, index, rule_id, scanner, severity))
    session.commit()
    session.refresh(scan)
    return scan


def _block(page: str, heading: str) -> str:
    """Содержимое секции с указанным заголовком."""
    start = page.index(heading)
    return page[start : page.index("</section>", start)]


def _row(block: str, marker: str) -> str:
    """Строка таблицы, в которой встречается marker (короткий SHA или правило)."""
    position = block.index(marker)
    start = block.rindex("<tr>", 0, position)
    return block[start : block.index("</tr>", start)]


@pytest.mark.integration
def test_fr_010_page_requires_session(db_client: AppClient) -> None:
    """Без cookie страница уводит на вход, как список проектов."""
    response = db_client.get("/projects/demo")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.integration
def test_fr_010_page_shows_runs_trend_and_top_rules(
    db_client: AppClient, db_session: Session
) -> None:
    """Три блока FR-010: прогоны, тренд по severity и топ-5 правил."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    old_sha = "a" * 40
    new_sha = "b" * 40
    _add_scan(
        db_session,
        project_id,
        commit_sha=old_sha,
        at=BASE_TIME,
        verdict="fail",
        counts={"critical": 3, "high": 1},
        findings=[
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-hardcoded-secret", "gitleaks", "high"),
        ],
    )
    _add_scan(
        db_session,
        project_id,
        commit_sha=new_sha,
        at=BASE_TIME + timedelta(days=1),
        verdict="pass",
        counts={"critical": 2, "medium": 1},
        findings=[
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-csrf", "semgrep", "medium"),
        ],
    )

    page = db_client.get("/projects/demo")

    assert page.status_code == 200
    assert "Демо" in page.text
    assert "demo" in page.text
    for heading in (RECENT_HEADING, TREND_HEADING, TOP_HEADING):
        assert heading in page.text

    # Русские подписи шкалы FR-014: CON-004.
    for label in ("критично", "высоко", "средне", "низко", "информационно"):
        assert label in page.text

    recent = _block(page.text, RECENT_HEADING)
    assert _row(recent, old_sha[:12]).count("<td") == 9
    assert "Задержан" in _row(recent, old_sha[:12])
    assert "Пропущен" in _row(recent, new_sha[:12])
    # Числа находок по severity и итог берутся из `scans.timings`.
    assert ">3<" in _row(recent, old_sha[:12])
    assert ">4<" in _row(recent, old_sha[:12])
    assert ">2<" in _row(recent, new_sha[:12])
    assert ">3<" in _row(recent, new_sha[:12])

    trend = _block(page.text, TREND_HEADING)
    # Тренд идёт от старых к новым: динамика читается сверху вниз.
    assert trend.index(old_sha[:12]) < trend.index(new_sha[:12])

    top = _block(page.text, TOP_HEADING)
    assert "rule-sql-injection" in top
    assert ">5<" in _row(top, "rule-sql-injection")
    assert "rule-hardcoded-secret" in top
    assert "rule-csrf" in top
    assert top.index("rule-sql-injection") < top.index("rule-csrf")


@pytest.mark.integration
def test_fr_010_foreign_project_is_forbidden(db_client: AppClient, db_session: Session) -> None:
    """Чужой проект отвечает 403 и не раскрывает ни прогонов, ни правил (FR-018)."""
    _create_user(db_session, "a@example.com")
    _create_user(db_session, "b@example.com")
    _login(db_client, "a@example.com")
    project_id = _create_project(db_client, "Проект А", "project-a")
    _add_scan(
        db_session,
        project_id,
        commit_sha="c" * 40,
        at=BASE_TIME,
        counts={"critical": 1},
        findings=[("rule-secret", "gitleaks", "critical")],
    )

    other = AppClient(app)
    _login(other, "b@example.com")
    response = other.get("/projects/project-a")

    assert response.status_code == 403
    assert "Проект А" not in response.text
    assert "c" * 12 not in response.text
    assert "rule-secret" not in response.text


@pytest.mark.integration
def test_fr_010_unknown_project_returns_404(db_client: AppClient, db_session: Session) -> None:
    _create_user(db_session, "user@example.com")
    _login(db_client, "user@example.com")

    response = db_client.get("/projects/no-such-project")

    assert response.status_code == 404
    assert "Проект не найден" in response.text


@pytest.mark.integration
def test_fr_010_page_without_runs_has_single_empty_state(
    db_client: AppClient, db_session: Session
) -> None:
    """Без прогонов — одно понятное пустое состояние вместо трёх блоков."""
    _create_user(db_session, "new@example.com")
    _login(db_client, "new@example.com")
    _create_project(db_client, "Пустой", "empty-project")

    page = db_client.get("/projects/empty-project")

    assert page.status_code == 200
    assert page.text.count('class="empty"') == 1
    assert "ещё нет досмотров" in page.text
    for heading in (RECENT_HEADING, TREND_HEADING, TOP_HEADING):
        assert heading not in page.text


@pytest.mark.integration
def test_fr_010_unfinished_runs_do_not_break_trend(
    db_client: AppClient, db_session: Session
) -> None:
    """`queued`, `running` и `error` не имеют метрик: тренд не падает и не выдумывает числа."""
    _create_user(db_session, "dev@example.com")
    _login(db_client, "dev@example.com")
    project_id = _create_project(db_client, "В работе", "in-progress")

    _add_scan(
        db_session,
        project_id,
        commit_sha="d" * 40,
        at=BASE_TIME,
        status="queued",
    )
    _add_scan(
        db_session,
        project_id,
        commit_sha="e" * 40,
        at=BASE_TIME + timedelta(hours=1),
        status="running",
    )
    _add_scan(
        db_session,
        project_id,
        commit_sha="f" * 40,
        at=BASE_TIME + timedelta(hours=2),
        status="error",
    )

    page = db_client.get("/projects/in-progress")

    assert page.status_code == 200
    recent = _block(page.text, RECENT_HEADING)
    for label in ("в очереди", "выполняется", "ошибка"):
        assert label in recent
    # У незавершённых прогонов числа не показываются.
    assert "—" in recent
    assert "Завершённых досмотров пока нет" in page.text
    assert TREND_HEADING not in page.text
    assert TOP_HEADING not in page.text


@pytest.mark.integration
def test_fr_010_top_rules_limited_to_five_over_last_ten_runs(
    db_client: AppClient, db_session: Session
) -> None:
    """Топ-5 считается по последним десяти `done`, а не по всей истории."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "История", "history")

    # Самый старый прогон выпадает из окна: его правило в топ не попадает.
    _add_scan(
        db_session,
        project_id,
        commit_sha="0" * 40,
        at=BASE_TIME,
        counts={"low": 1},
        findings=[("rule-old", "semgrep", "low")],
    )

    # В окне десять прогонов: правила a…f с убывающей частотой 10…5.
    frequencies = {
        "rule-a": 10,
        "rule-b": 9,
        "rule-c": 8,
        "rule-d": 7,
        "rule-e": 6,
        "rule-f": 5,
    }
    for day in range(1, 11):
        rules = [name for name, required in frequencies.items() if day <= required]
        _add_scan(
            db_session,
            project_id,
            commit_sha=f"{day:040d}",
            at=BASE_TIME + timedelta(days=day),
            counts={"low": len(rules)},
            findings=[(name, "semgrep", "low") for name in rules],
        )

    page = db_client.get("/projects/history")

    assert page.status_code == 200
    top = _block(page.text, TOP_HEADING)
    assert "rule-old" not in top
    for name in ("rule-a", "rule-b", "rule-c", "rule-d", "rule-e"):
        assert name in top
    # Шестое правило отсекает предел в пять строк.
    assert "rule-f" not in top
    assert ">10<" in _row(top, "rule-a")
    assert ">6<" in _row(top, "rule-e")


@pytest.mark.integration
def test_fr_010_page_does_not_show_other_projects_runs(
    db_client: AppClient, db_session: Session
) -> None:
    """Прогоны второго проекта того же пользователя не попадают на страницу первого."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    first = _create_project(db_client, "Первый", "first")
    second = _create_project(db_client, "Второй", "second")
    _add_scan(
        db_session,
        first,
        commit_sha="1" * 40,
        at=BASE_TIME,
        counts={"critical": 1},
    )
    _add_scan(
        db_session,
        second,
        commit_sha="2" * 40,
        at=BASE_TIME + timedelta(days=1),
        counts={"critical": 2},
    )

    page = db_client.get("/projects/first")

    assert page.status_code == 200
    assert "1" * 12 in page.text
    assert "2" * 12 not in page.text


@pytest.mark.integration
def test_fr_010_projects_list_links_to_project_page(
    db_client: AppClient, db_session: Session
) -> None:
    """Со списка проектов страница достижима ссылкой."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")

    page = db_client.get("/projects")

    assert page.status_code == 200
    assert 'href="/projects/demo"' in page.text


@pytest.mark.integration
def test_s_006_dashboard_shows_dynamics_on_two_runs(
    db_client: AppClient, db_session: Session
) -> None:
    """S-006: тимлид видит по двум прогонам, что находок стало меньше."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    first_sha = "7" * 40
    second_sha = "8" * 40
    _add_scan(
        db_session,
        project_id,
        commit_sha=first_sha,
        at=BASE_TIME,
        verdict="fail",
        counts={"critical": 4, "high": 2},
        findings=[
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-weak-hash", "semgrep", "high"),
            ("rule-weak-hash", "semgrep", "high"),
        ],
    )
    _add_scan(
        db_session,
        project_id,
        commit_sha=second_sha,
        at=BASE_TIME + timedelta(days=1),
        verdict="pass",
        counts={"critical": 2, "high": 1},
        findings=[
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-sql-injection", "semgrep", "critical"),
            ("rule-weak-hash", "semgrep", "high"),
        ],
    )

    page = db_client.get("/projects/demo")

    assert page.status_code == 200
    trend = _block(page.text, TREND_HEADING)
    assert trend.index(first_sha[:12]) < trend.index(second_sha[:12])
    first_row = _row(trend, first_sha[:12])
    second_row = _row(trend, second_sha[:12])
    assert ">4<" in first_row
    assert ">6<" in first_row
    assert ">2<" in second_row
    assert ">3<" in second_row
    assert "rule-sql-injection" in _block(page.text, TOP_HEADING)
