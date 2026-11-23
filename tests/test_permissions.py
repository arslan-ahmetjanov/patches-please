"""Единая проверка прав на проект: API и страницы (T-025, FR-017, FR-018).

Матрица доступа проверяется на одних и тех же трёх пользователях: владелец,
участник (`member`) и посторонний. Коды ответов зафиксированы поведением
T-022…T-024 и не меняются: владелец управляет, участник видит данные проекта,
посторонний в API получает 404, на страницах — 403. Отдельный тест следит,
чтобы в теле 403 и 404 не было ни названия проекта, ни slug, ни коммита,
ни правил, ни причин исключений.

Все тесты интеграционные: проверка читает `project_members`.
"""

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

import pytest
from conftest import AppClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.auth import service
from patches_please.auth.models import User
from patches_please.auth.permissions import (
    FORBIDDEN_MESSAGE,
    PROJECT_FORBIDDEN_MESSAGE,
    PROJECT_NOT_FOUND_MESSAGE,
    is_project_member,
    project_role,
)
from patches_please.main import app
from patches_please.metrics.service import SEVERITY_KEYS
from patches_please.policy.exceptions import create_exception
from patches_please.policy.models import ExceptionRecord, Policy
from patches_please.projects.models import MEMBER_ROLE, OWNER_ROLE, ProjectMember
from patches_please.scans.models import FindingRecord, Scan
from patches_please.tokens.models import ProjectToken
from patches_please.web.csrf import CSRF_FIELD_NAME

PASSWORD = "пароль-123"
PROJECT_NAME = "Секретный проект"
PROJECT_SLUG = "secret-project"
COMMIT_SHA = "e" * 40
RULE_ID = "rule-secret"
FINDING_MESSAGE = "Секрет в коде"
EXCEPTION_REASON = "секретная причина"
BASE_TIME = datetime(2026, 1, 10, 12, 0, tzinfo=UTC)
CSRF_RE = re.compile(rf'name="{CSRF_FIELD_NAME}" value="([^"]+)"')

# Тело ответа отказа не должно содержать ни одного из этих значений.
PROJECT_DATA_MARKERS: Final[tuple[str, ...]] = (
    PROJECT_NAME,
    PROJECT_SLUG,
    COMMIT_SHA[:12],
    RULE_ID,
    FINDING_MESSAGE,
    EXCEPTION_REASON,
)

POLICY_PAYLOAD = {
    "block_severities": ["critical"],
    "fail_mode": "open",
    "scanner_timeout_sec": 300,
}
POLICY_FORM = {
    "block_severities": ["critical"],
    "fail_mode": "open",
    "scanner_timeout_sec": "300",
}
EXCEPTION_FORM = {
    "rule_id": "rule-new",
    "path_glob": "src/*.py",
    "reason": "подтверждено",
    "expires_at": "2027-01-15T10:30",
}


@dataclass(frozen=True, slots=True)
class World:
    """Общая обстановка матрицы: три роли и данные проекта."""

    owner_id: uuid.UUID
    member_id: uuid.UUID
    stranger_id: uuid.UUID
    project_id: uuid.UUID
    scan_id: uuid.UUID
    exception_id: uuid.UUID
    member: AppClient
    stranger: AppClient


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


def _add_member(session: Session, project_id: uuid.UUID, user_id: uuid.UUID, role: str) -> None:
    """Членство добавляется напрямую: управления участниками в API ещё нет."""
    session.add(ProjectMember(project_id=project_id, user_id=user_id, role=role))
    session.commit()


def _add_scan(session: Session, project_id: uuid.UUID) -> Scan:
    """Завершённый прогон с находкой: странице есть что показать участнику."""
    counts = {severity: 0 for severity in SEVERITY_KEYS}
    counts["critical"] = 1
    scan = Scan(
        project_id=project_id,
        commit_sha=COMMIT_SHA,
        ref="refs/heads/main",
        provider="github",
        status="done",
        verdict="fail",
        timings={
            "duration_sec": 60.0,
            "findings_by_severity": counts,
            "new": 1,
            "fixed": 0,
            "excluded_ratio": 0.0,
        },
        created_at=BASE_TIME - timedelta(minutes=2),
        started_at=BASE_TIME - timedelta(minutes=1),
        finished_at=BASE_TIME,
    )
    session.add(scan)
    session.flush()
    session.add(
        FindingRecord(
            scan_id=scan.id,
            fingerprint=hashlib.sha256(str(scan.id).encode()).hexdigest(),
            scanner="semgrep",
            rule_id=RULE_ID,
            finding_type="sast",
            severity="critical",
            path="src/app.py",
            line=1,
            message=FINDING_MESSAGE,
            state="new",
            excluded=False,
        )
    )
    session.commit()
    session.refresh(scan)
    return scan


def _create_token(client: AppClient, project_id: uuid.UUID) -> uuid.UUID:
    response = client.post(f"/api/v1/projects/{project_id}/tokens", json={"name": "CI"})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _create_exception(
    session: Session, project_id: uuid.UUID, author_id: uuid.UUID
) -> ExceptionRecord:
    return create_exception(
        session,
        project_id=project_id,
        rule_id=RULE_ID,
        path_glob="src/*.py",
        reason=EXCEPTION_REASON,
        author_id=author_id,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )


def _csrf(client: AppClient, slug: str = PROJECT_SLUG) -> str:
    """Скрытый CSRF-токен со страницы настроек: форма и cookie из одного рендера."""
    page = client.get(f"/projects/{slug}/settings")
    assert page.status_code == 200, page.text
    match = CSRF_RE.search(page.text)
    assert match is not None, "на странице настроек нет скрытого поля CSRF"
    return match.group(1)


def _world(db_client: AppClient, session: Session) -> World:
    """Владелец, участник и посторонний; у проекта есть прогон и исключение."""
    owner = _create_user(session, "owner@example.com")
    member = _create_user(session, "member@example.com")
    stranger = _create_user(session, "stranger@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, PROJECT_NAME, PROJECT_SLUG)
    _add_member(session, project_id, member.id, MEMBER_ROLE)
    scan = _add_scan(session, project_id)
    record = _create_exception(session, project_id, author_id=owner.id)

    member_client = AppClient(app)
    _login(member_client, "member@example.com")
    stranger_client = AppClient(app)
    _login(stranger_client, "stranger@example.com")
    return World(
        owner_id=owner.id,
        member_id=member.id,
        stranger_id=stranger.id,
        project_id=project_id,
        scan_id=scan.id,
        exception_id=record.id,
        member=member_client,
        stranger=stranger_client,
    )


def _count(session: Session, model: type[Policy] | type[ExceptionRecord]) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


@pytest.mark.integration
def test_fr_018_project_role_and_membership(db_client: AppClient, db_session: Session) -> None:
    """Роль и членство берутся из одной строки `project_members`."""
    world = _world(db_client, db_session)

    assert project_role(db_session, world.project_id, world.owner_id) == OWNER_ROLE
    assert project_role(db_session, world.project_id, world.member_id) == MEMBER_ROLE
    assert project_role(db_session, world.project_id, world.stranger_id) is None
    assert project_role(db_session, uuid.uuid4(), world.owner_id) is None

    assert is_project_member(db_session, world.project_id, world.owner_id) is True
    assert is_project_member(db_session, world.project_id, world.member_id) is True
    assert is_project_member(db_session, world.project_id, world.stranger_id) is False
    assert is_project_member(db_session, uuid.uuid4(), world.owner_id) is False


@pytest.mark.integration
def test_fr_018_token_api_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """Токены: список — участнику, создание и отзыв — владельцу, чужой — 404."""
    world = _world(db_client, db_session)
    token_id = _create_token(db_client, world.project_id)
    tokens_url = f"/api/v1/projects/{world.project_id}/tokens"
    token_url = f"{tokens_url}/{token_id}"

    owner_list = db_client.get(tokens_url)
    assert owner_list.status_code == 200
    assert [item["id"] for item in owner_list.json()] == [str(token_id)]

    member_list = world.member.get(tokens_url)
    assert member_list.status_code == 200
    assert [item["id"] for item in member_list.json()] == [str(token_id)]

    member_create = world.member.post(tokens_url, json={"name": "Свой"})
    assert member_create.status_code == 403
    assert member_create.json() == {"detail": FORBIDDEN_MESSAGE}

    member_revoke = world.member.delete(token_url)
    assert member_revoke.status_code == 403
    assert member_revoke.json() == {"detail": FORBIDDEN_MESSAGE}

    stranger_list = world.stranger.get(tokens_url)
    assert stranger_list.status_code == 404
    assert stranger_list.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    stranger_create = world.stranger.post(tokens_url, json={"name": "Чужой"})
    assert stranger_create.status_code == 404
    assert stranger_create.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    stranger_revoke = world.stranger.delete(token_url)
    assert stranger_revoke.status_code == 404
    assert stranger_revoke.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    # Отказы ничего не изменили: токен владельца остался действующим.
    db_session.expire_all()
    assert db_session.get(ProjectToken, token_id).revoked_at is None

    owner_revoke = db_client.delete(token_url)
    assert owner_revoke.status_code == 204
    db_session.expire_all()
    assert db_session.get(ProjectToken, token_id).revoked_at is not None


@pytest.mark.integration
def test_fr_018_policy_api_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """`PUT` политики: владелец 200, участник 403, посторонний 404."""
    world = _world(db_client, db_session)
    url = f"/api/v1/projects/{world.project_id}/policy"

    stranger = world.stranger.put(url, json=POLICY_PAYLOAD)
    assert stranger.status_code == 404
    assert stranger.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    member = world.member.put(url, json=POLICY_PAYLOAD)
    assert member.status_code == 403
    assert member.json() == {"detail": FORBIDDEN_MESSAGE}
    assert _count(db_session, Policy) == 0

    owner = db_client.put(url, json=POLICY_PAYLOAD)
    assert owner.status_code == 200
    assert owner.json()["project_id"] == str(world.project_id)
    assert _count(db_session, Policy) == 1


@pytest.mark.integration
def test_fr_018_project_page_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """Страница проекта: владелец и участник видят, посторонний — 403."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}"

    for allowed in (db_client, world.member):
        response = allowed.get(url)
        assert response.status_code == 200
        assert PROJECT_NAME in response.text

    forbidden = world.stranger.get(url)
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": PROJECT_FORBIDDEN_MESSAGE}

    unknown = db_client.get("/projects/no-such-project")
    assert unknown.status_code == 404
    assert unknown.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_018_scan_page_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """Страница прогона: участнику 200, постороннему 403, неизвестный — 404."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}/scans/{world.scan_id}"

    for allowed in (db_client, world.member):
        response = allowed.get(url)
        assert response.status_code == 200
        assert RULE_ID in response.text

    forbidden = world.stranger.get(url)
    assert forbidden.status_code == 403
    assert forbidden.json() == {"detail": PROJECT_FORBIDDEN_MESSAGE}

    unknown = db_client.get(f"/projects/{PROJECT_SLUG}/scans/{uuid.uuid4()}")
    assert unknown.status_code == 404
    assert unknown.json() == {"detail": "Прогон не найден"}


@pytest.mark.integration
def test_fr_018_settings_page_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """Настройки: владелец 200, участник 403, посторонний и неизвестный — 404."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}/settings"

    owner = db_client.get(url)
    assert owner.status_code == 200
    assert PROJECT_NAME in owner.text

    member = world.member.get(url)
    assert member.status_code == 403
    assert member.json() == {"detail": FORBIDDEN_MESSAGE}

    stranger = world.stranger.get(url)
    assert stranger.status_code == 404
    assert stranger.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}

    unknown = db_client.get("/projects/no-such-project/settings")
    assert unknown.status_code == 404
    assert unknown.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}


@pytest.mark.integration
def test_fr_018_settings_policy_form_access_matrix(
    db_client: AppClient, db_session: Session
) -> None:
    """Форма политики: участник 403, посторонний 404, владелец сохраняет."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}/settings/policy"

    member = world.member.post(url, data=POLICY_FORM)
    assert member.status_code == 403
    assert member.json() == {"detail": FORBIDDEN_MESSAGE}

    stranger = world.stranger.post(url, data=POLICY_FORM)
    assert stranger.status_code == 404
    assert stranger.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}
    assert _count(db_session, Policy) == 0

    owner = db_client.post(url, data={**POLICY_FORM, "csrf_token": _csrf(db_client)})
    assert owner.status_code == 303
    assert _count(db_session, Policy) == 1


@pytest.mark.integration
def test_fr_018_settings_exception_form_access_matrix(
    db_client: AppClient, db_session: Session
) -> None:
    """Форма исключения: участник 403, посторонний 404, владелец создаёт."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}/settings/exceptions"

    member = world.member.post(url, data=EXCEPTION_FORM)
    assert member.status_code == 403
    assert member.json() == {"detail": FORBIDDEN_MESSAGE}

    stranger = world.stranger.post(url, data=EXCEPTION_FORM)
    assert stranger.status_code == 404
    assert stranger.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}
    assert _count(db_session, ExceptionRecord) == 1

    owner = db_client.post(url, data={**EXCEPTION_FORM, "csrf_token": _csrf(db_client)})
    assert owner.status_code == 303
    assert _count(db_session, ExceptionRecord) == 2


@pytest.mark.integration
def test_fr_018_exception_revoke_access_matrix(db_client: AppClient, db_session: Session) -> None:
    """Отзыв исключения: участник 403, посторонний 404, владелец отзывает."""
    world = _world(db_client, db_session)
    url = f"/projects/{PROJECT_SLUG}/settings/exceptions/{world.exception_id}/revoke"

    member = world.member.post(url, data={})
    assert member.status_code == 403
    assert member.json() == {"detail": FORBIDDEN_MESSAGE}

    stranger = world.stranger.post(url, data={})
    assert stranger.status_code == 404
    assert stranger.json() == {"detail": PROJECT_NOT_FOUND_MESSAGE}
    db_session.expire_all()
    assert db_session.get(ExceptionRecord, world.exception_id).revoked_at is None

    owner = db_client.post(url, data={"csrf_token": _csrf(db_client)})
    assert owner.status_code == 303
    db_session.expire_all()
    assert db_session.get(ExceptionRecord, world.exception_id).revoked_at is not None


@pytest.mark.integration
def test_fr_018_denied_responses_do_not_leak_project_data(
    db_client: AppClient, db_session: Session
) -> None:
    """403 и 404 не отдают названия проекта, slug, коммита, правил и причин."""
    world = _world(db_client, db_session)
    tokens_url = f"/api/v1/projects/{world.project_id}/tokens"
    policy_url = f"/api/v1/projects/{world.project_id}/policy"

    denied = [
        world.stranger.get(f"/projects/{PROJECT_SLUG}"),
        world.stranger.get(f"/projects/{PROJECT_SLUG}/scans/{world.scan_id}"),
        world.member.get(f"/projects/{PROJECT_SLUG}/settings"),
        world.stranger.get(f"/projects/{PROJECT_SLUG}/settings"),
        world.stranger.get(tokens_url),
        world.member.post(tokens_url, json={"name": "Чужой"}),
        world.stranger.put(policy_url, json=POLICY_PAYLOAD),
    ]

    for response in denied:
        assert response.status_code in (403, 404), response.text
        assert response.json()["detail"] in {
            PROJECT_NOT_FOUND_MESSAGE,
            FORBIDDEN_MESSAGE,
            PROJECT_FORBIDDEN_MESSAGE,
        }
        for marker in PROJECT_DATA_MARKERS:
            assert marker not in response.text
