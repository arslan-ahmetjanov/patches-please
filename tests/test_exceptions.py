"""Исключения находок: обязательные поля, срок и аудит (T-015, FR-011, FR-012, S-005).

Чистые тесты проверяют предикат `is_excluded` на доменных находках без базы,
интеграционные — создание, отзыв, выборку активных и записи журнала через
`db_session` с откатываемой транзакцией, как в `tests/test_baseline.py`.

S-005 проверяется на уровне исключений: активное исключение снимает находку,
истёкшее и отозванное — нет, оба действия попадают в журнал. Связка с вердиктом
появляется в T-017, поэтому здесь вердикт не вычисляется.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from patches_please.audit.models import AuditEvent
from patches_please.auth.models import User
from patches_please.normalize.fingerprint import compute_fingerprint
from patches_please.normalize.model import Finding, FindingType, Severity
from patches_please.policy.exceptions import (
    AUDIT_EXCEPTION_CREATED,
    AUDIT_EXCEPTION_REVOKED,
    ExceptionNotFoundError,
    ExceptionValidationError,
    active_exceptions,
    create_exception,
    is_excluded,
    revoke_exception,
)
from patches_please.policy.models import ExceptionRecord
from patches_please.projects.models import Project

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)
LATER = NOW + timedelta(days=30)
EARLIER = NOW - timedelta(days=1)


def _finding(*, rule_id: str = "rule-1", path: str = "src/app.py") -> Finding:
    """Находка с заполненными обязательными полями FR-003."""
    return Finding(
        scanner="semgrep",
        rule_id=rule_id,
        severity=Severity.HIGH,
        path=path,
        line=10,
        message="Опасный вызов",
        finding_type=FindingType.SAST,
        fingerprint=compute_fingerprint("semgrep", rule_id, path, "dangerous_call()"),
    )


def _exception(
    *,
    rule_id: str = "rule-1",
    path_glob: str = "src/*.py",
    expires_at: datetime = LATER,
    revoked_at: datetime | None = None,
) -> ExceptionRecord:
    """Несохранённое исключение для проверки предиката без базы."""
    return ExceptionRecord(
        project_id=uuid.uuid4(),
        rule_id=rule_id,
        path_glob=path_glob,
        reason="ложное срабатывание",
        author_id=uuid.uuid4(),
        expires_at=expires_at,
        revoked_at=revoked_at,
    )


def _user(session: Session) -> User:
    user = User(email=f"author-{uuid.uuid4().hex[:8]}@example.com", password_hash="hash")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _project(session: Session) -> Project:
    project = Project(name="Демо", slug=f"demo-{uuid.uuid4().hex[:8]}")
    session.add(project)
    session.commit()
    session.refresh(project)
    return project


def _create(
    session: Session,
    project: Project,
    author: User,
    **overrides: Any,
) -> ExceptionRecord:
    """Создаёт исключение с корректными значениями по умолчанию."""
    values: dict[str, Any] = {
        "project_id": project.id,
        "rule_id": "rule-1",
        "path_glob": "src/*.py",
        "reason": "ложное срабатывание",
        "author_id": author.id,
        "expires_at": LATER,
    }
    values.update(overrides)
    return create_exception(session, **values)


# --- FR-011: обязательные поля и шаблон пути -------------------------------------


@pytest.mark.integration
def test_fr_011_create_persists_all_mandatory_fields(db_session: Session) -> None:
    """Исключение сохраняется с правилом, путём, причиной, автором и сроком."""
    project = _project(db_session)
    author = _user(db_session)

    record = _create(db_session, project, author)

    assert record.id is not None
    assert record.project_id == project.id
    assert record.rule_id == "rule-1"
    assert record.path_glob == "src/*.py"
    assert record.reason == "ложное срабатывание"
    assert record.author_id == author.id
    assert record.expires_at == LATER
    assert record.revoked_at is None
    assert db_session.get(ExceptionRecord, record.id) is not None


@pytest.mark.integration
@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"rule_id": ""}, "правило"),
        ({"rule_id": "   "}, "правило"),
        ({"path_glob": ""}, "путь"),
        ({"reason": ""}, "причина"),
        ({"reason": "   "}, "причина"),
        ({"author_id": None}, "автор"),
        ({"expires_at": None}, "срок действия"),
        ({"expires_at": datetime(2026, 11, 23, 12, 0)}, "часовой пояс"),
    ],
)
def test_fr_011_create_rejects_missing_mandatory_field(
    db_session: Session,
    overrides: dict[str, Any],
    field: str,
) -> None:
    """Пустое обязательное поле отклоняется с указанием поля из FR-011."""
    project = _project(db_session)
    author = _user(db_session)

    with pytest.raises(ExceptionValidationError, match=field):
        _create(db_session, project, author, **overrides)

    count = db_session.scalar(select(func.count()).select_from(ExceptionRecord))
    assert count == 0


@pytest.mark.integration
def test_fr_011_missing_reason_rejected_with_field_name(db_session: Session) -> None:
    """Сценарий FR-011: без причины сохранение отклонено, поле названо."""
    project = _project(db_session)
    author = _user(db_session)

    with pytest.raises(ExceptionValidationError, match="причина"):
        _create(db_session, project, author, reason="")


def test_fr_011_path_glob_matches_rule_and_path_only() -> None:
    """Исключение действует только на своё правило и подходящий путь."""
    finding = _finding(rule_id="rule-1", path="src/app.py")

    assert is_excluded(finding, [_exception(rule_id="rule-1", path_glob="src/*.py")], NOW)
    assert not is_excluded(finding, [_exception(rule_id="rule-2", path_glob="src/*.py")], NOW)
    assert not is_excluded(finding, [_exception(rule_id="rule-1", path_glob="tests/*")], NOW)


def test_fr_011_path_glob_is_case_sensitive_and_star_crosses_directories() -> None:
    """`fnmatchcase`: регистр важен, `*` совпадает и с `/` — поведение зафиксировано."""
    nested = _finding(path="src/pkg/app.py")

    assert is_excluded(nested, [_exception(path_glob="src/*.py")], NOW)
    assert not is_excluded(nested, [_exception(path_glob="SRC/*.py")], NOW)


# --- FR-012: активное, истёкшее и отозванное исключение ---------------------------


def test_fr_012_active_exception_excludes_finding() -> None:
    """Действующее исключение снимает находку до истечения срока."""
    assert is_excluded(_finding(), [_exception(expires_at=LATER)], NOW)


def test_fr_012_expired_exception_does_not_exclude_finding() -> None:
    """Истёкшее вчера исключение находку не снимает: она снова учитывается."""
    assert not is_excluded(_finding(), [_exception(expires_at=EARLIER)], NOW)


def test_fr_012_exception_is_inactive_at_expiry_moment() -> None:
    """В сам момент истечения исключение уже не действует: граница строгая."""
    assert not is_excluded(_finding(), [_exception(expires_at=NOW)], NOW)


def test_fr_012_revoked_exception_does_not_exclude_finding() -> None:
    """Отозванное исключение не действует, даже если срок ещё не истёк."""
    assert not is_excluded(_finding(), [_exception(expires_at=LATER, revoked_at=NOW)], NOW)


@pytest.mark.integration
def test_fr_012_active_exceptions_skips_expired_and_revoked(db_session: Session) -> None:
    """Выборка на момент прогона отдаёт только действующие исключения проекта."""
    project = _project(db_session)
    author = _user(db_session)
    active = _create(db_session, project, author)
    expired = _create(db_session, project, author, rule_id="rule-expired", expires_at=EARLIER)
    revoked = _create(db_session, project, author, rule_id="rule-revoked")
    revoke_exception(db_session, revoked.id, actor=author.id, now=NOW)

    selected = active_exceptions(db_session, project.id, now=NOW)

    assert {record.id for record in selected} == {active.id}
    assert expired.id not in {record.id for record in selected}


# --- FR-011, S-005: журнал аудита -------------------------------------------------


@pytest.mark.integration
def test_fr_011_create_writes_audit_event_without_secrets(db_session: Session) -> None:
    """Создание пишет событие с явным набором полей; причина и секреты не копируются."""
    project = _project(db_session)
    author = _user(db_session)
    marker = "pp_secret_token_123"

    record = _create(db_session, project, author, reason=f"ложное срабатывание, {marker}")

    events = list(db_session.scalars(select(AuditEvent)))
    assert len(events) == 1
    event = events[0]
    assert event.actor == author.id
    assert event.action == AUDIT_EXCEPTION_CREATED
    assert event.entity == f"exception:{record.id}"
    assert event.payload == {
        "project_id": str(project.id),
        "rule_id": "rule-1",
        "path_glob": "src/*.py",
        "expires_at": LATER.isoformat(),
    }
    assert marker not in json.dumps(event.payload)
    assert "reason" not in event.payload


@pytest.mark.integration
def test_fr_011_revoke_writes_audit_event(db_session: Session) -> None:
    """Отзыв фиксирует время и актора отдельным событием журнала."""
    project = _project(db_session)
    author = _user(db_session)
    record = _create(db_session, project, author)

    revoked = revoke_exception(db_session, record.id, actor=author.id, now=NOW)

    assert revoked.revoked_at == NOW
    event = db_session.scalars(
        select(AuditEvent).where(AuditEvent.action == AUDIT_EXCEPTION_REVOKED)
    ).one()
    assert event.actor == author.id
    assert event.entity == f"exception:{record.id}"
    assert event.payload == {
        "project_id": str(project.id),
        "revoked_at": NOW.isoformat(),
    }


@pytest.mark.integration
def test_fr_011_revoke_rejects_unknown_exception(db_session: Session) -> None:
    """Отзыв несуществующего исключения — ошибка, а не молчаливый пропуск."""
    author = _user(db_session)

    with pytest.raises(ExceptionNotFoundError):
        revoke_exception(db_session, uuid.uuid4(), actor=author.id, now=NOW)


@pytest.mark.integration
def test_s_005_active_exception_silences_then_expiry_restores_finding(
    db_session: Session,
) -> None:
    """S-005: активное исключение снимает находку, после срока она снова учитывается."""
    project = _project(db_session)
    author = _user(db_session)
    finding = _finding(path="src/app.py")
    record = _create(
        db_session,
        project,
        author,
        rule_id=finding.rule_id,
        path_glob=finding.path,
        expires_at=NOW + timedelta(days=1),
    )

    active = active_exceptions(db_session, project.id, now=NOW)
    assert is_excluded(finding, active, NOW)

    after_expiry = active_exceptions(db_session, project.id, now=NOW + timedelta(days=2))
    assert not is_excluded(finding, after_expiry, NOW + timedelta(days=2))
    assert db_session.scalar(select(func.count()).select_from(AuditEvent)) == 1
    assert record.revoked_at is None
