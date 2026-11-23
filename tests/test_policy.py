"""Политика проекта и вердикт прогона (T-017, FR-004, FR-014).

Чистые тесты проверяют `compute_verdict` на доменных строках находок без базы:
ровно два значения вердикта, блокирующий уровень из политики, игнорирование
`existing` и `excluded`. Интеграционные — хранение порогов по проектам,
умолчание `critical`+`high`, заполнение `excluded` по исключениям, запись
`scans.verdict` и API `PUT /api/v1/projects/{id}/policy` с правами владельца.

Сценарии S-002/S-003/S-005 проверяются здесь на уровне вердикта: baseline
не блокирует, действующее исключение не блокирует, новая критическая находка
при порогах по умолчанию — `fail`. Коды выхода CI и деградация сканеров —
T-018/T-019, в этом файле их нет.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from conftest import AppClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.auth import service as auth_service
from patches_please.auth.models import User
from patches_please.main import app
from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.baseline import install_baseline
from patches_please.policy.classify import FindingState, classify
from patches_please.policy.exceptions import create_exception
from patches_please.policy.models import Policy
from patches_please.policy.verdict import (
    DEFAULT_POLICY,
    FailMode,
    PolicyError,
    Verdict,
    apply_exceptions,
    compute_verdict,
    load_policy,
    save_verdict,
    upsert_policy,
)
from patches_please.projects.models import MEMBER_ROLE, Project, ProjectMember
from patches_please.scans.findings import save_findings
from patches_please.scans.models import FindingRecord, Scan
from patches_please.scans.service import mark_done, mark_running
from patches_please.tokens import service as token_service

PASSWORD = "пароль-123"
SHA = "d" * 40


def _finding(index: int, *, severity: Severity = Severity.HIGH) -> Finding:
    """Находка с уникальным fingerprint: путь и правило зависят от индекса."""
    rule_id = f"rule-{index}"
    path = f"src/module_{index}.py"
    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=1,
        message=f"Находка {rule_id}",
        finding_type=FindingType.SAST,
        fingerprint=compute_fingerprint("semgrep", rule_id, path, f"dangerous_call({index})"),
    )


def _record(
    *,
    severity: Severity,
    state: FindingState = FindingState.NEW,
    excluded: bool = False,
) -> FindingRecord:
    """Несохранённая строка находки для чистой проверки вердикта."""
    return FindingRecord(
        scan_id=uuid.uuid4(),
        fingerprint="f" * 64,
        scanner="semgrep",
        rule_id="rule-1",
        finding_type=str(FindingType.SAST),
        severity=str(severity),
        path="src/app.py",
        line=1,
        message="Опасный вызов",
        state=str(state),
        excluded=excluded,
    )


def _project(session: Session) -> Project:
    project = Project(name="Демо", slug=f"demo-{uuid.uuid4().hex[:8]}")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _queued_scan(session: Session, project: Project) -> Scan:
    """Прогон в статусе `queued`: проект нужен ради внешнего ключа."""
    scan = Scan(
        project_id=project.id,
        commit_sha=SHA,
        ref="refs/heads/main",
        provider="github",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def _done_scan(session: Session, project: Project) -> Scan:
    scan = _queued_scan(session, project)
    mark_running(session, scan)
    mark_done(session, scan)
    return scan


def _store(
    session: Session,
    scan: Scan,
    findings: list[Finding],
    *,
    base: list[str] | None = None,
) -> list[FindingRecord]:
    """Сохраняет находки прогона; без базы все находки новые."""
    return save_findings(session, scan, classify(findings, base or []))


def _create_user(session: Session, email: str) -> User:
    return auth_service.create_user(session, email, PASSWORD)


def _login(client: AppClient, email: str) -> None:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text


def _create_project(client: AppClient, name: str, slug: str) -> uuid.UUID:
    response = client.post("/api/v1/projects", json={"name": name, "slug": slug})
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def _add_member(session: Session, project_id: uuid.UUID, user: User, role: str) -> None:
    session.add(ProjectMember(project_id=project_id, user_id=user.id, role=role))
    session.commit()


# --- FR-004: два значения вердикта и его источники --------------------------------


def test_fr_004_verdict_has_exactly_two_values() -> None:
    """Вердикт — ровно `pass` или `fail`, без промежуточных значений."""
    assert {verdict.value for verdict in Verdict} == {"pass", "fail"}


def test_fr_004_new_blocking_finding_gives_fail() -> None:
    """Новая находка блокирующего уровня делает вердикт `fail`."""
    record = _record(severity=Severity.HIGH)

    assert compute_verdict([record], {Severity.HIGH}) is Verdict.FAIL


def test_fr_004_existing_and_excluded_findings_do_not_change_verdict() -> None:
    """Находки из базы и находки под исключением вердикт не меняют."""
    records = [
        _record(severity=Severity.CRITICAL, state=FindingState.EXISTING),
        _record(severity=Severity.CRITICAL, excluded=True),
    ]

    assert compute_verdict(records, {Severity.CRITICAL}) is Verdict.PASS


def test_fr_004_empty_run_gives_pass() -> None:
    """Пустой прогон проходит: блокировать нечему."""
    assert compute_verdict([], {Severity.CRITICAL, Severity.HIGH}) is Verdict.PASS


# --- FR-014: пороги по severity отдельно для каждого проекта ----------------------


def test_fr_014_same_finding_gives_different_verdicts_for_different_thresholds() -> None:
    """Одна находка `high`: строгий порог блокирует, мягкий — нет."""
    record = _record(severity=Severity.HIGH)

    strict = compute_verdict([record], {Severity.CRITICAL, Severity.HIGH})
    lenient = compute_verdict([record], {Severity.CRITICAL})

    assert strict is Verdict.FAIL
    assert lenient is Verdict.PASS


@pytest.mark.integration
def test_fr_014_policies_are_stored_per_project(db_session: Session) -> None:
    """Два проекта с разными порогами дают разные вердикты на одной находке."""
    strict_project = _project(db_session)
    lenient_project = _project(db_session)
    upsert_policy(
        db_session,
        strict_project.id,
        block_severities=[Severity.CRITICAL, Severity.HIGH],
    )
    upsert_policy(db_session, lenient_project.id, block_severities=[Severity.CRITICAL])

    finding = _finding(0, severity=Severity.HIGH)
    strict_scan = _done_scan(db_session, strict_project)
    lenient_scan = _done_scan(db_session, lenient_project)
    _store(db_session, strict_scan, [finding])
    _store(db_session, lenient_scan, [finding])

    assert save_verdict(db_session, strict_scan) is Verdict.FAIL
    assert save_verdict(db_session, lenient_scan) is Verdict.PASS
    assert load_policy(db_session, strict_project.id).block_severities == frozenset(
        {Severity.CRITICAL, Severity.HIGH}
    )
    assert load_policy(db_session, lenient_project.id).block_severities == frozenset(
        {Severity.CRITICAL}
    )


@pytest.mark.integration
def test_fr_014_default_policy_blocks_critical_and_high(db_session: Session) -> None:
    """Без строки политики действует умолчание S-002: блокируются critical и high."""
    project = _project(db_session)
    assert load_policy(db_session, project.id) == DEFAULT_POLICY

    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0, severity=Severity.HIGH)])

    assert save_verdict(db_session, scan) is Verdict.FAIL


@pytest.mark.integration
def test_fr_014_default_policy_lets_medium_through(db_session: Session) -> None:
    """Уровень ниже `high` при умолчании не блокирует."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0, severity=Severity.MEDIUM)])

    assert save_verdict(db_session, scan) is Verdict.PASS


@pytest.mark.integration
def test_fr_014_upsert_replaces_single_row_and_normalizes_levels(
    db_session: Session,
) -> None:
    """Повторная запись переиспользует строку, убирает дубли и держит порядок шкалы."""
    project = _project(db_session)

    first = upsert_policy(
        db_session,
        project.id,
        block_severities=[Severity.INFO, Severity.CRITICAL, Severity.CRITICAL],
        fail_mode=FailMode.CLOSED,
        scanner_timeout_sec=120,
    )
    # Значения первой записи снимаем до второй: объект в сессии тот же самый.
    first_levels = list(first.block_severities)
    first_timeout = first.scanner_timeout_sec
    second = upsert_policy(db_session, project.id, block_severities=[Severity.MEDIUM])

    assert first_levels == ["critical", "info"]
    assert first_timeout == 120
    assert second.project_id == first.project_id
    assert second.block_severities == ["medium"]
    assert second.fail_mode == "open"
    assert second.scanner_timeout_sec == 300

    rows = list(db_session.scalars(select(Policy).where(Policy.project_id == project.id)))
    assert len(rows) == 1


@pytest.mark.integration
def test_fr_014_upsert_rejects_non_positive_timeout(db_session: Session) -> None:
    """Таймаут сканеров должен быть положительным."""
    project = _project(db_session)

    with pytest.raises(PolicyError, match="положительным"):
        upsert_policy(db_session, project.id, block_severities=[], scanner_timeout_sec=0)


# --- FR-006, S-003: baseline не блокирует -----------------------------------------


@pytest.mark.integration
def test_fr_004_existing_findings_do_not_fail_verdict(db_session: Session) -> None:
    """Находка из установленного baseline помечается `existing` и не блокирует."""
    project = _project(db_session)
    finding = _finding(0, severity=Severity.CRITICAL)

    baseline_scan = _done_scan(db_session, project)
    _store(db_session, baseline_scan, [finding])
    install_baseline(db_session, baseline_scan)

    current = _done_scan(db_session, project)
    records = _store(db_session, current, [finding], base=[finding.fingerprint])

    assert records[0].state == FindingState.EXISTING
    assert save_verdict(db_session, current) is Verdict.PASS


# --- FR-011, S-005: исключение снимает находку с вердикта -------------------------


@pytest.mark.integration
def test_fr_004_excluded_findings_do_not_fail_verdict(db_session: Session) -> None:
    """Действующее исключение проставляет `excluded` и снимает находку с вердикта."""
    project = _project(db_session)
    author = _create_user(db_session, "author@example.com")
    finding = _finding(0, severity=Severity.CRITICAL)
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [finding])
    create_exception(
        db_session,
        project_id=project.id,
        rule_id=finding.rule_id,
        path_glob="src/*.py",
        reason="ложное срабатывание",
        author_id=author.id,
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )

    assert apply_exceptions(db_session, scan) == 1
    stored = db_session.scalar(select(FindingRecord).where(FindingRecord.scan_id == scan.id))
    assert stored is not None
    assert stored.excluded is True
    assert save_verdict(db_session, scan) is Verdict.PASS


# --- FR-004: запись вердикта ------------------------------------------------------


@pytest.mark.integration
def test_fr_004_save_verdict_persists_result(db_session: Session) -> None:
    """Вердикт пишется в `scans.verdict` и повторный вызов даёт тот же ответ."""
    project = _project(db_session)
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0, severity=Severity.CRITICAL)])
    scan_id = scan.id

    assert save_verdict(db_session, scan) is Verdict.FAIL
    assert scan.verdict == "fail"

    db_session.expire_all()
    reloaded = db_session.get(Scan, scan_id)
    assert reloaded is not None
    assert reloaded.verdict == "fail"
    assert save_verdict(db_session, reloaded) is Verdict.FAIL


@pytest.mark.integration
@pytest.mark.parametrize("status", ["queued", "running"])
def test_fr_004_save_verdict_rejects_unfinished_scan(db_session: Session, status: str) -> None:
    """Вердикт по незавершённому прогону не выносится: набор находок неполон."""
    project = _project(db_session)
    scan = _queued_scan(db_session, project)
    if status == "running":
        mark_running(db_session, scan)

    with pytest.raises(PolicyError, match="только по завершённому прогону"):
        save_verdict(db_session, scan)


# --- FR-004, FR-014: API политики -------------------------------------------------


@pytest.mark.integration
def test_fr_014_put_policy_requires_session(db_client: AppClient) -> None:
    """Без cookie сессии метод отвечает 401, а не 404."""
    response = db_client.put(
        f"/api/v1/projects/{uuid.uuid4()}/policy",
        json={"block_severities": ["critical"]},
    )

    assert response.status_code == 401


@pytest.mark.integration
def test_fr_014_put_policy_sets_and_replaces(db_client: AppClient, db_session: Session) -> None:
    """Владелец задаёт политику целиком; повторный PUT заменяет ту же строку."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    response = db_client.put(
        f"/api/v1/projects/{project_id}/policy",
        json={
            "block_severities": ["critical", "high"],
            "fail_mode": "closed",
            "scanner_timeout_sec": 120,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body == {
        "project_id": str(project_id),
        "block_severities": ["critical", "high"],
        "fail_mode": "closed",
        "scanner_timeout_sec": 120,
    }

    replaced = db_client.put(
        f"/api/v1/projects/{project_id}/policy",
        json={"block_severities": ["medium"]},
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["block_severities"] == ["medium"]
    assert replaced.json()["fail_mode"] == "open"
    assert replaced.json()["scanner_timeout_sec"] == 300

    rows = list(db_session.scalars(select(Policy).where(Policy.project_id == project_id)))
    assert len(rows) == 1
    assert rows[0].block_severities == ["medium"]


@pytest.mark.integration
def test_fr_014_put_policy_foreign_project_is_404(
    db_client: AppClient, db_session: Session
) -> None:
    """Посторонний не видит чужой проект: 404, как у токенов."""
    _create_user(db_session, "owner@example.com")
    owner = AppClient(app)
    _login(owner, "owner@example.com")
    project_id = _create_project(owner, "Демо", "demo")

    _create_user(db_session, "stranger@example.com")
    stranger = AppClient(app)
    _login(stranger, "stranger@example.com")

    response = stranger.put(
        f"/api/v1/projects/{project_id}/policy",
        json={"block_severities": ["critical"]},
    )

    assert response.status_code == 404


@pytest.mark.integration
def test_fr_014_put_policy_member_is_403(db_client: AppClient, db_session: Session) -> None:
    """Участник проекта политику не правит: 403."""
    _create_user(db_session, "owner@example.com")
    member = _create_user(db_session, "member@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    _add_member(db_session, project_id, member, MEMBER_ROLE)

    member_client = AppClient(app)
    _login(member_client, "member@example.com")
    response = member_client.put(
        f"/api/v1/projects/{project_id}/policy",
        json={"block_severities": ["critical"]},
    )

    assert response.status_code == 403


@pytest.mark.integration
@pytest.mark.parametrize(
    "payload",
    [
        {"block_severities": ["blocker"]},
        {"block_severities": ["critical"], "scanner_timeout_sec": 0},
    ],
)
def test_fr_014_put_policy_invalid_values_are_422(
    db_client: AppClient, db_session: Session, payload: dict[str, object]
) -> None:
    """Неизвестный уровень и нулевой таймаут отклоняются на границе API."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")

    response = db_client.put(f"/api/v1/projects/{project_id}/policy", json=payload)

    assert response.status_code == 422
    for error in response.json()["detail"]:
        assert set(error) == {"type", "loc", "msg"}


# --- FR-004, FR-007: вердикт виден в ответе о прогоне -----------------------------


@pytest.mark.integration
def test_fr_004_verdict_is_visible_in_scan_response(
    db_client: AppClient, db_session: Session
) -> None:
    """`GET /api/v1/scans/{id}` отдаёт сохранённый вердикт по токену проекта."""
    _create_user(db_session, "owner@example.com")
    _login(db_client, "owner@example.com")
    project_id = _create_project(db_client, "Демо", "demo")
    token, _ = token_service.create_token(db_session, project_id, "CI")

    project = db_session.get(Project, project_id)
    assert project is not None
    scan = _done_scan(db_session, project)
    _store(db_session, scan, [_finding(0, severity=Severity.CRITICAL)])
    assert save_verdict(db_session, scan) is Verdict.FAIL

    response = db_client.get(
        f"/api/v1/scans/{scan.id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["verdict"] == "fail"
