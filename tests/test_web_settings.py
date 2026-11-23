"""Страница настроек: политика и исключения (T-024, FR-011, FR-014, FR-018).

Страница одна на две формы: политика вердикта и исключения находок. Тесты
проверяют то, что обещает задача: умолчание политики, сохранение порогов,
400 с сохранёнными значениями при ошибке формы, обязательные поля исключения,
отзыв исключения, CSRF-защиту и `Secure` у cookie вне локального стенда.

Все тесты интеграционные: страница читает и пишет базу, а форма исключения
нужна автору из сессии.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from conftest import AppClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.auth.models import User
from patches_please.main import app
from patches_please.policy.exceptions import (
    active_exceptions,
    create_exception,
    revoke_exception,
)
from patches_please.policy.models import ExceptionRecord, Policy
from patches_please.policy.verdict import FailMode, load_policy
from patches_please.projects.models import MEMBER_ROLE, ProjectMember
from patches_please.web.csrf import CSRF_COOKIE_NAME, CSRF_FIELD_NAME

PASSWORD = "пароль-123"
CSRF_RE = re.compile(rf'name="{CSRF_FIELD_NAME}" value="([^"]+)"')


def _create_user(session: Session, email: str) -> User:
    """Учётная запись для входа: регистрации нет, пользователя заводит тест."""
    return service.create_user(session, email, PASSWORD)


def _login(client: AppClient, email: str) -> uuid.UUID:
    """Вход через API; возвращает id пользователя для проверки авторства."""
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return uuid.UUID(response.json()["id"])


def _create_project(client: AppClient, name: str, slug: str) -> uuid.UUID:
    response = client.post("/api/v1/projects", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _add_member(session: Session, project_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Второй участник проекта: роль `member`, настроек он не меняет."""
    session.add(ProjectMember(project_id=project_id, user_id=user_id, role=MEMBER_ROLE))
    session.commit()


def _csrf(page: str) -> str:
    """Скрытый токен из формы: cookie и поле выдаёт один и тот же рендер."""
    match = CSRF_RE.search(page)
    assert match is not None, "на странице настроек нет скрытого поля CSRF"
    return match.group(1)


def _row(tbody: str, marker: str) -> str:
    """Строка таблицы, в которой встречается marker (правило)."""
    position = tbody.index(marker)
    start = tbody.rindex("<tr>", 0, position)
    return tbody[start : tbody.index("</tr>", start)]


def _settings_token(client: AppClient, slug: str = "demo") -> str:
    page = client.get(f"/projects/{slug}/settings")
    assert page.status_code == 200, page.text
    return _csrf(page.text)


def _post_policy(
    client: AppClient,
    token: str,
    *,
    severities: list[str] | None = None,
    fail_mode: str = "open",
    timeout: str = "300",
) -> httpx.Response:
    data: dict[str, Any] = {
        "csrf_token": token,
        "fail_mode": fail_mode,
        "scanner_timeout_sec": timeout,
    }
    if severities is not None:
        data["block_severities"] = severities
    return client.post("/projects/demo/settings/policy", data=data)


def _post_exception(
    client: AppClient,
    token: str,
    *,
    rule_id: str = "rule-1",
    path_glob: str = "src/*.py",
    reason: str = "ложное срабатывание",
    expires_at: str = "2027-01-15T10:30",
) -> httpx.Response:
    return client.post(
        "/projects/demo/settings/exceptions",
        data={
            "csrf_token": token,
            "rule_id": rule_id,
            "path_glob": path_glob,
            "reason": reason,
            "expires_at": expires_at,
        },
    )


@pytest.mark.integration
def test_fr_014_settings_page_shows_default_policy(
    db_client: AppClient, db_session: Session
) -> None:
    """Владелец видит умолчание: critical и high, fail-open, таймаут 300."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")

    page = db_client.get("/projects/demo/settings")

    assert page.status_code == 200
    assert "Настройки" in page.text
    assert 'name="block_severities"' in page.text
    assert 'value="critical" checked' in page.text
    assert 'value="high" checked' in page.text
    assert 'value="medium" checked' not in page.text
    assert 'value="low" checked' not in page.text
    assert '<option value="open" selected>' in page.text
    assert 'value="300"' in page.text
    assert "Исключений нет" in page.text
    assert CSRF_COOKIE_NAME in page.cookies


@pytest.mark.integration
def test_fr_011_settings_page_lists_exceptions_with_author_and_state(
    db_client: AppClient, db_session: Session
) -> None:
    """Таблица исключений показывает правило, путь, причину, автора и состояние."""
    author = _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    moment = datetime.now(UTC)
    create_exception(
        db_session,
        project_id=project_id,
        rule_id="rule-active",
        path_glob="src/*.py",
        reason="ложное срабатывание",
        author_id=author.id,
        expires_at=moment + timedelta(days=30),
    )
    create_exception(
        db_session,
        project_id=project_id,
        rule_id="rule-expired",
        path_glob="tests/*.py",
        reason="срок вышел",
        author_id=author.id,
        expires_at=moment - timedelta(days=1),
    )
    revoked = create_exception(
        db_session,
        project_id=project_id,
        rule_id="rule-revoked",
        path_glob="docs/*",
        reason="отозвано вручную",
        author_id=author.id,
        expires_at=moment + timedelta(days=30),
    )
    revoke_exception(db_session, revoked.id, actor=author.id)

    page = db_client.get("/projects/demo/settings")

    assert page.status_code == 200
    for marker in ("rule-active", "rule-expired", "rule-revoked"):
        assert marker in page.text
    assert "src/*.py" in page.text
    assert "ложное срабатывание" in page.text
    assert author.email in page.text
    assert "действует" in page.text
    assert "истёк" in page.text
    assert "отозван" in page.text
    # Активное исключение можно отозвать, отозванное — уже нет.
    rows = page.text[page.text.index("<tbody>") : page.text.index("</tbody>")]
    assert "/revoke" in _row(rows, "rule-active")
    assert "/revoke" in _row(rows, "rule-expired")
    assert "/revoke" not in _row(rows, "rule-revoked")


@pytest.mark.integration
def test_fr_018_settings_page_is_owner_only(db_client: AppClient, db_session: Session) -> None:
    """Участник без роли owner получает 403, посторонний и неизвестный slug — 404."""
    _create_user(db_session, "owner@example.com")
    member = _create_user(db_session, "member@example.com")
    _create_user(db_session, "stranger@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    _add_member(db_session, project_id, member.id)

    owner_page = db_client.get("/projects/demo/settings")
    assert owner_page.status_code == 200

    member_client = AppClient(app)
    _login(member_client, "member@example.com")
    forbidden = member_client.get("/projects/demo/settings")
    assert forbidden.status_code == 403
    assert "Демо" not in forbidden.text

    stranger_client = AppClient(app)
    _login(stranger_client, "stranger@example.com")
    stranger = stranger_client.get("/projects/demo/settings")
    assert stranger.status_code == 404
    assert "Демо" not in stranger.text
    assert "Проект не найден" in stranger.text

    unknown = db_client.get("/projects/no-such-project/settings")
    assert unknown.status_code == 404
    assert "Проект не найден" in unknown.text


@pytest.mark.integration
def test_fr_018_settings_page_requires_session(db_client: AppClient) -> None:
    """Без cookie страница настроек уводит на вход, как остальные страницы."""
    response = db_client.get("/projects/demo/settings")

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


@pytest.mark.integration
def test_fr_014_policy_form_saves_thresholds(db_client: AppClient, db_session: Session) -> None:
    """Форма сохраняет набор блокирующих уровней, режим и таймаут."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_policy(
        db_client,
        token,
        severities=["critical", "low"],
        fail_mode="closed",
        timeout="120",
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/projects/demo/settings"
    policy = load_policy(db_session, project_id)
    assert {str(severity) for severity in policy.block_severities} == {"critical", "low"}
    assert policy.fail_mode is FailMode.CLOSED
    assert policy.scanner_timeout_sec == 120

    page = db_client.get("/projects/demo/settings")
    assert 'value="critical" checked' in page.text
    assert 'value="low" checked' in page.text
    assert 'value="high" checked' not in page.text
    assert '<option value="closed" selected>' in page.text
    assert 'value="120"' in page.text


@pytest.mark.integration
def test_fr_014_policy_form_allows_no_blocking_severities(
    db_client: AppClient, db_session: Session
) -> None:
    """Пустой набор уровней — допустимая политика, а не ошибка формы."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_policy(db_client, token, severities=None, fail_mode="open")

    assert response.status_code == 303
    policy = load_policy(db_session, project_id)
    assert policy.block_severities == frozenset()


@pytest.mark.integration
@pytest.mark.parametrize("timeout", ["", "abc", "0", "-5", "1.5"])
def test_fr_014_policy_form_rejects_invalid_timeout(
    db_client: AppClient, db_session: Session, timeout: str
) -> None:
    """Неположительный или нецелый таймаут — 400, значения формы не теряются."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_policy(
        db_client,
        token,
        severities=["high"],
        fail_mode="closed",
        timeout=timeout,
    )

    assert response.status_code == 400
    assert "Таймаут сканеров" in response.text
    assert "Таймаут сканеров должен быть целым положительным числом" in response.text
    assert 'value="high" checked' in response.text
    assert 'value="critical" checked' not in response.text
    assert '<option value="closed" selected>' in response.text
    # Политика не записана: страница показала умолчание, значит строки нет.
    assert db_session.scalar(select(func.count()).select_from(Policy)) == 0


@pytest.mark.integration
def test_fr_014_policy_form_rejects_unknown_severity(
    db_client: AppClient, db_session: Session
) -> None:
    """Неизвестный уровень — 400 с перечнем допустимых значений."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_policy(db_client, token, severities=["critical", "urgent"])

    assert response.status_code == 400
    assert "Неизвестная важность: urgent" in response.text
    assert "Допустимые значения: critical, high, medium, low, info" in response.text
    assert db_session.scalar(select(func.count()).select_from(Policy)) == 0


@pytest.mark.integration
def test_fr_011_exception_form_saves_all_fields(db_client: AppClient, db_session: Session) -> None:
    """Исключение сохраняет правило, путь, причину, автора и срок."""
    author = _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_exception(db_client, token, expires_at="2027-01-15T10:30")

    assert response.status_code == 303
    assert response.headers["location"] == "/projects/demo/settings"
    record = db_session.scalars(select(ExceptionRecord)).one()
    assert record.project_id == project_id
    assert record.rule_id == "rule-1"
    assert record.path_glob == "src/*.py"
    assert record.reason == "ложное срабатывание"
    assert record.author_id == author.id
    assert record.expires_at == datetime(2027, 1, 15, 10, 30, tzinfo=UTC)
    assert record.revoked_at is None

    page = db_client.get("/projects/demo/settings")
    assert "rule-1" in page.text
    assert "ложное срабатывание" in page.text
    assert "действует" in page.text


@pytest.mark.integration
def test_fr_011_exception_form_requires_reason(db_client: AppClient, db_session: Session) -> None:
    """Без причины — 400, поле названо, строка в БД не появляется."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_exception(db_client, token, reason="")

    assert response.status_code == 400
    assert "Поле «причина» обязательно" in response.text
    assert db_session.scalar(select(func.count()).select_from(ExceptionRecord)) == 0
    # Введённые значения возвращаются в форму.
    assert 'value="rule-1"' in response.text
    assert 'value="src/*.py"' in response.text
    assert 'value="2027-01-15T10:30"' in response.text


@pytest.mark.integration
def test_fr_011_exception_form_requires_expiry(db_client: AppClient, db_session: Session) -> None:
    """Без срока действия исключение не сохраняется: поле названо (FR-011)."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    response = _post_exception(db_client, token, expires_at="")

    assert response.status_code == 400
    assert "Поле «срок действия» обязательно" in response.text
    assert db_session.scalar(select(func.count()).select_from(ExceptionRecord)) == 0


@pytest.mark.integration
def test_fr_011_exception_can_be_revoked(db_client: AppClient, db_session: Session) -> None:
    """После отзыва исключение не считается активным и остаётся в истории."""
    author = _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    now = datetime.now(UTC)
    record = create_exception(
        db_session,
        project_id=project_id,
        rule_id="rule-1",
        path_glob="src/*.py",
        reason="ложное срабатывание",
        author_id=author.id,
        expires_at=now + timedelta(days=30),
    )
    token = _settings_token(db_client)

    response = db_client.post(
        f"/projects/demo/settings/exceptions/{record.id}/revoke",
        data={"csrf_token": token},
    )

    assert response.status_code == 303
    db_session.refresh(record)
    assert record.revoked_at is not None
    assert active_exceptions(db_session, project_id, now=datetime.now(UTC)) == []

    page = db_client.get("/projects/demo/settings")
    assert "rule-1" in page.text
    assert "отозван" in page.text


@pytest.mark.integration
def test_fr_018_exception_from_another_project_is_not_revocable(
    db_client: AppClient, db_session: Session
) -> None:
    """Исключение чужого проекта по угаданному id даёт 404 и не меняется."""
    author = _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Первый", "first")
    other_project = _create_project(db_client, "Второй", "second")
    record = create_exception(
        db_session,
        project_id=other_project,
        rule_id="rule-second",
        path_glob="src/*.py",
        reason="чужое исключение",
        author_id=author.id,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    token = _settings_token(db_client, slug="first")

    response = db_client.post(
        f"/projects/first/settings/exceptions/{record.id}/revoke",
        data={"csrf_token": token},
    )

    assert response.status_code == 404
    assert "Исключение не найдено" in response.text
    db_session.refresh(record)
    assert record.revoked_at is None


@pytest.mark.integration
def test_fr_014_settings_forms_reject_missing_csrf(
    db_client: AppClient, db_session: Session
) -> None:
    """Без CSRF-токена формы отвечают 403 и ничего не пишут."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    token = _settings_token(db_client)

    policy = db_client.post(
        "/projects/demo/settings/policy",
        data={"block_severities": ["critical"], "fail_mode": "open", "scanner_timeout_sec": "300"},
    )
    exception = db_client.post(
        "/projects/demo/settings/exceptions",
        data={
            "rule_id": "rule-1",
            "path_glob": "src/*.py",
            "reason": "без токена",
            "expires_at": "2027-01-15T10:30",
        },
    )
    forged = _post_policy(db_client, "подделка")

    for response in (policy, exception, forged):
        assert response.status_code == 403
        assert "CSRF" in response.text
    assert db_session.scalar(select(func.count()).select_from(Policy)) == 0
    assert db_session.scalar(select(func.count()).select_from(ExceptionRecord)) == 0
    # Токен из формы без cookie тоже не проходит.
    db_client.clear_cookies()
    _login(db_client, "owner@example.com")
    no_cookie = _post_policy(db_client, token)
    assert no_cookie.status_code == 403


@pytest.mark.integration
def test_fr_018_session_cookie_is_secure_outside_local(
    db_client: AppClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Вне local cookie сессии получает Secure: демо-стенд работает по HTTPS."""
    monkeypatch.setenv("APP_ENV", "demo")
    _create_user(db_session, "owner@example.com")

    response = db_client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": PASSWORD},
    )

    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]


@pytest.mark.integration
def test_fr_018_session_cookie_is_not_secure_locally(
    db_client: AppClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Локальный стенд по HTTP не ставит Secure: иначе браузер cookie не вернёт."""
    monkeypatch.setenv("APP_ENV", "local")
    _create_user(db_session, "owner@example.com")

    response = db_client.post(
        "/api/v1/auth/login",
        json={"email": "owner@example.com", "password": PASSWORD},
    )

    assert response.status_code == 200
    assert "Secure" not in response.headers["set-cookie"]


@pytest.mark.integration
def test_fr_018_csrf_cookie_is_secure_outside_local(
    db_client: AppClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cookie CSRF получает Secure вместе с сессией: атрибуты не расходятся."""
    monkeypatch.setenv("APP_ENV", "local")
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")
    monkeypatch.setenv("APP_ENV", "demo")

    page = db_client.get("/projects/demo/settings")

    assert page.status_code == 200
    assert CSRF_COOKIE_NAME in page.headers["set-cookie"]
    assert "Secure" in page.headers["set-cookie"]


@pytest.mark.integration
def test_fr_014_project_page_links_to_settings(db_client: AppClient, db_session: Session) -> None:
    """Со страницы проекта владелец открывает настройки ссылкой в шапке."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    _create_project(db_client, "Демо", "demo")

    page = db_client.get("/projects/demo")

    assert page.status_code == 200
    assert '<a href="/projects/demo/settings">Настройки</a>' in page.text
