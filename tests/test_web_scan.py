"""Страница прогона: находки, фильтры и права (T-023, FR-003, FR-018).

Страница строится по сохранённым строкам `findings` и `scans.timings`:
демо-репозитория (T-032) и живого прогона пока нет, поэтому данные готовятся
тестовой базой так же, как их оставляет конвейер T-038.

Проверяется то, что обещает задача: шесть полей FR-003, состояние и сообщение,
фильтры по severity и состоянию по отдельности и вместе, различимые пустые
состояния и запрет на данные чужого проекта (FR-018). Все тесты интеграционные,
кроме отдачи фирменного CSS: она не читает базу (T-037).
"""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

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

# Таблица находок на странице помечена id: по нему тесты отделяют её от шапки
# и формы фильтров, где тоже встречаются русские подписи уровней и состояний.
FINDINGS_SECTION = '<section id="findings">'
BRAND_CSS_URL = "/static/brand.css"


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


def _timings(
    counts: dict[str, int],
    *,
    new: int,
    fixed: int,
    excluded_ratio: float = 0.0,
) -> dict[str, Any]:
    """Метрики в том виде, в каком их пишет `save_metrics` (FR-015)."""
    return {
        "duration_sec": 60.0,
        "findings_by_severity": {severity: counts.get(severity, 0) for severity in SEVERITY_KEYS},
        "new": new,
        "fixed": fixed,
        "excluded_ratio": excluded_ratio,
    }


def _add_scan(
    session: Session,
    project_id: uuid.UUID,
    *,
    commit_sha: str = "a" * 40,
    status: str = "done",
    verdict: str = "fail",
    counts: dict[str, int] | None = None,
    new: int = 0,
    fixed: int = 0,
) -> Scan:
    """Прогон в нужном статусе; метрики пишутся только для `done`."""
    started_at = None
    finished_at = None
    timings = None
    if status in ("done", "error"):
        started_at = BASE_TIME - timedelta(minutes=1)
        finished_at = BASE_TIME
    if status == "done" and counts is not None:
        timings = _timings(counts, new=new, fixed=fixed)

    scan = Scan(
        project_id=project_id,
        commit_sha=commit_sha,
        ref="refs/heads/main",
        provider="github",
        status=status,
        verdict=verdict if status == "done" else None,
        error="Сканер упал" if status == "error" else None,
        timings=timings,
        created_at=BASE_TIME - timedelta(minutes=2),
        started_at=started_at,
        finished_at=finished_at,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _add_finding(
    session: Session,
    scan: Scan,
    index: int,
    *,
    rule_id: str,
    severity: str,
    scanner: str = "semgrep",
    finding_type: str = "sast",
    path: str = "src/app.py",
    line: int | None = None,
    message: str | None = None,
    state: str = "new",
    excluded: bool = False,
) -> FindingRecord:
    """Находка с уникальным fingerprint: пара (прогон, индекс) уникальна."""
    record = FindingRecord(
        scan_id=scan.id,
        fingerprint=hashlib.sha256(f"{scan.id}:{index}".encode()).hexdigest(),
        scanner=scanner,
        rule_id=rule_id,
        finding_type=finding_type,
        severity=severity,
        path=path,
        line=index + 1 if line is None else line,
        message=message or f"Находка {rule_id}",
        state=state,
        excluded=excluded,
    )
    session.add(record)
    session.commit()
    return record


def _tbody(page: str) -> str:
    """Только строки таблицы: подписи фильтров и заголовки в проверку не входят."""
    start = page.index("<tbody>")
    return page[start : page.index("</tbody>", start)]


def _row(tbody: str, marker: str) -> str:
    """Строка таблицы, в которой встречается marker (правило)."""
    position = tbody.index(marker)
    start = tbody.rindex("<tr>", 0, position)
    return tbody[start : tbody.index("</tr>", start)]


def test_con_004_brand_css_is_served(client: AppClient) -> None:
    """Фирменный CSS отдаётся с `/static` и содержит токены паспорта стиля (T-037)."""
    response = client.get(BRAND_CSS_URL)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    for token in ("#faf7f0", "#b3261e", "Pixelify Sans", "IBM Plex Sans"):
        assert token in response.text


@pytest.mark.integration
def test_fr_018_scan_page_requires_session(db_client: AppClient) -> None:
    """Без cookie страница прогона уводит на вход, как страница проекта."""
    response = db_client.get(f"/projects/demo/scans/{uuid.uuid4()}")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.integration
def test_fr_003_scan_page_shows_all_finding_fields(
    db_client: AppClient, db_session: Session
) -> None:
    """Находки показывают шесть полей FR-003, состояние и сообщение."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(
        db_session,
        project_id,
        counts={"critical": 1, "high": 1},
        new=1,
        fixed=2,
    )
    _add_finding(
        db_session,
        scan,
        0,
        rule_id="rule-sql-injection",
        severity="critical",
        scanner="semgrep",
        finding_type="sast",
        path="src/db.py",
        line=42,
        message="SQL-инъекция в запросе",
        state="new",
    )
    _add_finding(
        db_session,
        scan,
        1,
        rule_id="rule-hardcoded-secret",
        severity="high",
        scanner="gitleaks",
        finding_type="secrets",
        path="src/config.py",
        line=7,
        message="Секрет в коде",
        state="existing",
        excluded=True,
    )

    page = db_client.get(f"/projects/demo/scans/{scan.id}")

    assert page.status_code == 200
    assert "Демо" in page.text
    assert scan.commit_sha[:12] in page.text

    rows = _tbody(page.text)
    # Шесть полей FR-003: важность, правило, путь, строка, тип, сканер.
    assert "критично" in rows
    assert "rule-sql-injection" in rows
    assert "src/db.py" in rows
    assert ">42<" in rows
    assert "sast" in rows
    assert "semgrep" in rows
    assert "rule-hardcoded-secret" in rows
    assert "src/config.py" in rows
    assert ">7<" in rows
    assert "secrets" in rows
    assert "gitleaks" in rows
    # Состояние, признак исключения и сообщение.
    assert "Исключена" in page.text
    assert "новая" in rows
    assert "существовала" in rows
    assert "SQL-инъекция в запросе" in rows
    assert "Секрет в коде" in rows
    assert "<td>нет</td>" in _row(rows, "rule-sql-injection")
    assert "да" in _row(rows, "rule-hardcoded-secret")
    # Тяжёлая находка идёт первой.
    assert rows.index("rule-sql-injection") < rows.index("rule-hardcoded-secret")
    # Счётчик исправленных берётся из `scans.timings`.
    assert "исправленных: 2" in page.text


@pytest.mark.integration
@pytest.mark.parametrize(
    ("verdict", "label", "stamp_class"),
    [("pass", "Пропущен", "stamp-pass"), ("fail", "Задержан", "stamp-fail")],
)
def test_con_004_scan_page_shows_verdict_stamp(
    db_client: AppClient,
    db_session: Session,
    verdict: str,
    label: str,
    stamp_class: str,
) -> None:
    """Штамп вердикта на странице досмотра: слово из словаря и класс цвета (T-037)."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, verdict=verdict, counts={"critical": 1}, new=1)

    page = db_client.get(f"/projects/demo/scans/{scan.id}")

    assert page.status_code == 200
    assert f'href="{BRAND_CSS_URL}"' in page.text
    assert f'class="stamp {stamp_class}"' in page.text
    assert label in page.text
    assert ">pass<" not in page.text
    assert ">fail<" not in page.text


@pytest.mark.integration
def test_fr_003_done_scan_without_metrics_still_shows_findings(
    db_client: AppClient, db_session: Session
) -> None:
    """Отсутствие `scans.timings` не скрывает находки и не роняет страницу."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    # counts=None — у завершённого прогона нет сохранённых метрик.
    scan = _add_scan(db_session, project_id, counts=None)
    _add_finding(db_session, scan, 0, rule_id="rule-sql-injection", severity="critical")

    page = db_client.get(f"/projects/demo/scans/{scan.id}")

    assert page.status_code == 200
    assert "Метрики досмотра недоступны" in page.text
    assert "rule-sql-injection" in _tbody(page.text)


@pytest.mark.integration
def test_fr_003_finding_text_is_escaped(db_client: AppClient, db_session: Session) -> None:
    """Текст находки из репозитория экранируется, а не вставляется как HTML."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 1}, new=1)
    message = '<script>alert("xss")</script>'
    path = "src/<img src=x>.py"
    _add_finding(
        db_session,
        scan,
        0,
        rule_id="rule-sql-injection",
        severity="critical",
        path=path,
        message=message,
    )

    page = db_client.get(f"/projects/demo/scans/{scan.id}")

    assert page.status_code == 200
    assert message not in page.text
    assert path not in page.text
    assert "&lt;script&gt;" in page.text
    assert "&lt;img src=x&gt;" in page.text


@pytest.mark.integration
def test_fr_003_severity_filter_selects_one_level(
    db_client: AppClient, db_session: Session
) -> None:
    """Фильтр severity оставляет только выбранный уровень."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 1, "high": 1}, new=2)
    _add_finding(db_session, scan, 0, rule_id="rule-sql-injection", severity="critical")
    _add_finding(db_session, scan, 1, rule_id="rule-weak-hash", severity="high")

    page = db_client.get(f"/projects/demo/scans/{scan.id}?severity=critical")

    assert page.status_code == 200
    rows = _tbody(page.text)
    assert "rule-sql-injection" in rows
    assert "rule-weak-hash" not in rows
    assert "Показано 1 из 2." in page.text
    assert 'value="critical" selected' in page.text


@pytest.mark.integration
def test_fr_003_state_filter_selects_new_or_existing(
    db_client: AppClient, db_session: Session
) -> None:
    """Фильтр state оставляет только выбранную метку классификации."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 2, "high": 1}, new=2)
    _add_finding(db_session, scan, 0, rule_id="rule-new", severity="critical", state="new")
    _add_finding(
        db_session, scan, 1, rule_id="rule-existing", severity="critical", state="existing"
    )
    _add_finding(db_session, scan, 2, rule_id="rule-new-high", severity="high", state="new")

    page = db_client.get(f"/projects/demo/scans/{scan.id}?state=existing")

    assert page.status_code == 200
    rows = _tbody(page.text)
    assert "rule-existing" in rows
    assert "rule-new" not in rows
    assert "rule-new-high" not in rows
    assert "Показано 1 из 3." in page.text
    assert 'value="existing" selected' in page.text


@pytest.mark.integration
def test_fr_003_severity_and_state_filters_combine(
    db_client: AppClient, db_session: Session
) -> None:
    """Фильтры severity и state работают вместе, а не по очереди."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 2, "high": 1}, new=2)
    _add_finding(db_session, scan, 0, rule_id="rule-critical-new", severity="critical", state="new")
    _add_finding(
        db_session, scan, 1, rule_id="rule-critical-old", severity="critical", state="existing"
    )
    _add_finding(db_session, scan, 2, rule_id="rule-high-new", severity="high", state="new")

    page = db_client.get(f"/projects/demo/scans/{scan.id}?severity=critical&state=new")

    assert page.status_code == 200
    rows = _tbody(page.text)
    assert "rule-critical-new" in rows
    assert "rule-critical-old" not in rows
    assert "rule-high-new" not in rows
    assert "Показано 1 из 3." in page.text


@pytest.mark.integration
def test_fr_003_empty_filter_values_show_all_findings(
    db_client: AppClient, db_session: Session
) -> None:
    """Пустые значения формы «все» — не фильтр: страница показывает всё."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 1, "high": 1}, new=1)
    _add_finding(db_session, scan, 0, rule_id="rule-critical", severity="critical")
    _add_finding(db_session, scan, 1, rule_id="rule-high", severity="high", state="existing")

    page = db_client.get(f"/projects/demo/scans/{scan.id}?severity=&state=")

    assert page.status_code == 200
    rows = _tbody(page.text)
    assert "rule-critical" in rows
    assert "rule-high" in rows
    assert "Показано 2 из 2." in page.text


@pytest.mark.integration
@pytest.mark.parametrize(
    ("query", "message"),
    [
        ("severity=urgent", "Неизвестная важность"),
        ("state=fixed", "не хранится в находках прогона"),
        ("state=unknown", "Неизвестное состояние"),
    ],
)
def test_fr_003_unknown_filter_value_is_rejected(
    db_client: AppClient, db_session: Session, query: str, message: str
) -> None:
    """Опечатка в фильтре — понятный 400, а не 500 и не молчаливая выдача."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 1}, new=1)
    _add_finding(db_session, scan, 0, rule_id="rule-sql-injection", severity="critical")

    response = db_client.get(f"/projects/demo/scans/{scan.id}?{query}")

    assert response.status_code == 400
    assert message in response.text
    assert "rule-sql-injection" not in response.text


@pytest.mark.integration
def test_fr_003_empty_scan_and_empty_filter_result_differ(
    db_client: AppClient, db_session: Session
) -> None:
    """«Находок нет» и «по фильтру ничего не найдено» — разные состояния."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    empty_scan = _add_scan(db_session, project_id, counts={}, new=0)
    filled_scan = _add_scan(
        db_session,
        project_id,
        commit_sha="b" * 40,
        counts={"critical": 1},
        new=1,
    )
    _add_finding(db_session, filled_scan, 0, rule_id="rule-sql-injection", severity="critical")

    empty_page = db_client.get(f"/projects/demo/scans/{empty_scan.id}")
    filtered_page = db_client.get(f"/projects/demo/scans/{filled_scan.id}?severity=low")

    assert empty_page.status_code == 200
    assert "Находок нет." in empty_page.text
    assert "По фильтру ничего не найдено." not in empty_page.text
    # Без находок форма фильтров не нужна.
    assert 'name="severity"' not in empty_page.text

    assert filtered_page.status_code == 200
    assert "По фильтру ничего не найдено." in filtered_page.text
    assert "Находок нет." not in filtered_page.text
    assert 'name="severity"' in filtered_page.text
    assert "Сбросить" in filtered_page.text


@pytest.mark.integration
@pytest.mark.parametrize(
    ("status", "label"),
    [
        ("queued", "в очереди"),
        ("running", "выполняется"),
        ("error", "ошибка"),
    ],
)
def test_fr_003_unfinished_scan_has_no_findings_table(
    db_client: AppClient, db_session: Session, status: str, label: str
) -> None:
    """У `queued`, `running`, `error` нет ложной таблицы находок."""
    _create_user(db_session, "lead@example.com")
    _login(db_client, "lead@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, status=status)

    page = db_client.get(f"/projects/demo/scans/{scan.id}")

    assert page.status_code == 200
    assert label in page.text
    assert FINDINGS_SECTION not in page.text
    assert "<table" not in page.text
    assert "Находки" not in page.text
    if status == "error":
        assert "Причина: Сканер упал" in page.text


@pytest.mark.integration
def test_fr_018_foreign_project_scan_is_forbidden(
    db_client: AppClient, db_session: Session
) -> None:
    """Прогон чужого проекта отвечает 403 и не раскрывает данные (FR-018)."""
    _create_user(db_session, "a@example.com")
    _create_user(db_session, "b@example.com")
    _login(db_client, "a@example.com")
    project_id = _create_project(db_client, "Проект А", "project-a")
    scan = _add_scan(db_session, project_id, commit_sha="c" * 40, counts={"critical": 1}, new=1)
    _add_finding(
        db_session,
        scan,
        0,
        rule_id="rule-secret",
        severity="critical",
        message="Секрет в коде",
    )

    other = AppClient(app)
    _login(other, "b@example.com")
    response = other.get(f"/projects/project-a/scans/{scan.id}")

    assert response.status_code == 403
    assert "Проект А" not in response.text
    assert "c" * 12 not in response.text
    assert "rule-secret" not in response.text
    assert "Секрет в коде" not in response.text


@pytest.mark.integration
def test_fr_018_unknown_project_and_scan_return_404(
    db_client: AppClient, db_session: Session
) -> None:
    """Неизвестный проект, неизвестный и битый идентификатор прогона — 404."""
    _create_user(db_session, "user@example.com")
    _login(db_client, "user@example.com")
    _create_project(db_client, "Демо", "demo")

    unknown_project = db_client.get(f"/projects/no-such-project/scans/{uuid.uuid4()}")
    unknown_scan = db_client.get(f"/projects/demo/scans/{uuid.uuid4()}")
    malformed = db_client.get("/projects/demo/scans/not-a-uuid")

    assert unknown_project.status_code == 404
    assert "Проект не найден" in unknown_project.text
    assert unknown_scan.status_code == 404
    assert "Прогон не найден" in unknown_scan.text
    assert malformed.status_code == 404
    assert "Прогон не найден" in malformed.text


@pytest.mark.integration
def test_fr_018_scan_is_scoped_to_its_project(db_client: AppClient, db_session: Session) -> None:
    """Прогон другого проекта того же пользователя по чужому slug не открывается."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Первый", "first")
    second = _create_project(db_client, "Второй", "second")
    foreign_scan = _add_scan(
        db_session,
        second,
        commit_sha="d" * 40,
        counts={"critical": 1},
        new=1,
    )
    _add_finding(db_session, foreign_scan, 0, rule_id="rule-second", severity="critical")

    response = db_client.get(f"/projects/first/scans/{foreign_scan.id}")

    assert response.status_code == 404
    assert "rule-second" not in response.text
    assert "d" * 12 not in response.text


@pytest.mark.integration
def test_fr_003_scan_page_is_reachable_from_project_page(
    db_client: AppClient, db_session: Session
) -> None:
    """Со страницы проекта прогон открывается ссылкой из истории."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    scan = _add_scan(db_session, project_id, counts={"critical": 1}, new=1)

    page = db_client.get("/projects/demo")

    assert page.status_code == 200
    assert f'href="/projects/demo/scans/{scan.id}"' in page.text
