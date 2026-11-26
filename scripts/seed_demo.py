"""Наполнение демо-стенда Patches, Please (T-032, CON-003).

Скрипт создаёт или обновляет демо-учётную запись, проект, токен CI и, по
запросу, baseline. Он работает с базой напрямую: регистрации в API нет, а
baseline ставится сервисной функцией `install_baseline`, а не методом REST.
Поэтому запускать его нужно там, где доступна PostgreSQL стенда, — с хоста
после `docker compose up -d` и `uv run alembic upgrade head`.

Идемпотентность: повторный запуск с теми же параметрами не создаёт дублей.
Пользователь ищется по email, проект — по slug, токен — по имени. Пароль
существующего пользователя приводится к значению из окружения, проект — к
адресу репозитория и ветке из окружения, членство — к роли `owner`.

Токен показывается один раз: в базе лежит только SHA-256. Если действующий
токен с нужным именем уже есть, скрипт его не пересоздаёт — иначе каждый
запуск плодил бы неиспользуемые ключи. Новый токен выдаётся с `--rotate-token`:
старые действующие токены с этим именем отзываются.

Baseline ставится только по завершённому прогону (`done`) и только по явной
просьбе: `--baseline-latest` берёт последний завершённый прогон проекта,
`--baseline-scan <uuid>` — указанный. Без флага baseline не меняется.

Параметры берутся из окружения; пароль и адрес репозитория обязательны,
секретов в файле нет:

    DATABASE_URL          строка подключения; по умолчанию локальный стенд
                          из `patches_please/db.py`
    DEMO_EMAIL            email демо-пользователя, по умолчанию demo@example.com
    DEMO_PASSWORD         пароль демо-пользователя, обязателен, не короче 8 символов
    DEMO_PROJECT_NAME     название проекта, по умолчанию «Демо: сервис Заметки»
    DEMO_PROJECT_SLUG     slug проекта, по умолчанию patches-please-demo
    DEMO_REPO_URL         адрес демо-репозитория, обязателен
    DEMO_DEFAULT_BRANCH   ветка по умолчанию, по умолчанию main
    DEMO_TOKEN_NAME       имя токена CI, по умолчанию ci

Код возврата: 0 — данные приведены к нужному состоянию; 1 — ошибка параметров,
подключения или baseline.

Примеры:

    DEMO_PASSWORD='...' \
    DEMO_REPO_URL='https://github.com/arslan-ahmetjanov/patches-please-demo.git' \
    uv run python scripts/seed_demo.py

    uv run python scripts/seed_demo.py --baseline-latest
"""

import argparse
import os
import sys
import uuid
from typing import Final

from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from patches_please.auth.models import User
from patches_please.auth.service import create_user, hash_password, verify_password
from patches_please.db import build_engine, database_url
from patches_please.policy.baseline import BaselineError, install_baseline
from patches_please.projects.models import OWNER_ROLE, Project, ProjectMember
from patches_please.projects.router import ProjectCreate, ProjectSlugTakenError, create_project
from patches_please.scans.models import Scan
from patches_please.scans.service import ScanStatus
from patches_please.tokens.models import ProjectToken
from patches_please.tokens.service import create_token, revoke_token

DEFAULT_EMAIL: Final = "demo@example.com"
DEFAULT_PROJECT_NAME: Final = "Демо: сервис Заметки"
DEFAULT_PROJECT_SLUG: Final = "patches-please-demo"
DEFAULT_BRANCH: Final = "main"
DEFAULT_TOKEN_NAME: Final = "ci"
MIN_PASSWORD_LENGTH: Final = 8
# Без явного таймаута psycopg ждёт недоступный порт минутами: для служебного
# скрипта лучше быстро сообщить, что база не поднята.
CONNECT_TIMEOUT_SEC: Final = 10


class SeedError(Exception):
    """Параметры окружения или данные стенда не позволяют выполнить наполнение."""


def _env(name: str, default: str | None = None) -> str:
    """Значение из окружения; пустое значение считается отсутствующим."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    if default is None:
        raise SeedError(f"{name} не задан")
    return default


def _password_from_env() -> str:
    """Пароль демо-пользователя: обязателен и не короче минимума."""
    password = _env("DEMO_PASSWORD")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise SeedError(f"DEMO_PASSWORD короче {MIN_PASSWORD_LENGTH} символов")
    return password


def _project_payload() -> ProjectCreate:
    """Параметры проекта с той же валидацией, что у API."""
    try:
        return ProjectCreate(
            name=_env("DEMO_PROJECT_NAME", DEFAULT_PROJECT_NAME),
            slug=_env("DEMO_PROJECT_SLUG", DEFAULT_PROJECT_SLUG),
            repo_url=_env("DEMO_REPO_URL"),
            default_branch=_env("DEMO_DEFAULT_BRANCH", DEFAULT_BRANCH),
        )
    except ValidationError as error:
        raise SeedError(f"некорректные параметры проекта: {error}") from error


def _ensure_user(session: Session, email: str, password: str) -> User:
    """Находит или создаёт пользователя; пароль приводит к значению из окружения."""
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        user = create_user(session, email, password)
        print(f"пользователь создан: {user.email}")
        return user

    if not verify_password(password, user.password_hash):
        user.password_hash = hash_password(password)
        session.commit()
        print(f"пользователь найден: {user.email}; пароль обновлён")
    else:
        print(f"пользователь найден: {user.email}")
    return user


def _ensure_membership(session: Session, project: Project, user: User) -> None:
    """Владелец проекта должен быть участником с ролью `owner`."""
    membership = session.get(ProjectMember, (project.id, user.id))
    if membership is None:
        session.add(ProjectMember(project_id=project.id, user_id=user.id, role=OWNER_ROLE))
        session.commit()
        print("членство создано: owner")
        return
    if membership.role != OWNER_ROLE:
        membership.role = OWNER_ROLE
        session.commit()
        print(f"роль членства обновлена: {OWNER_ROLE}")


def _ensure_project(session: Session, payload: ProjectCreate, user: User) -> Project:
    """Находит или создаёт проект и приводит его технические поля к окружению."""
    project = session.scalar(select(Project).where(Project.slug == payload.slug))
    if project is None:
        try:
            project = create_project(session, payload, user)
        except ProjectSlugTakenError:
            # Гонка: slug заняли между выборкой и вставкой. Перечитываем строку,
            # чтобы повторный запуск не падал трейсбеком.
            project = session.scalar(select(Project).where(Project.slug == payload.slug))
            if project is None:
                raise SeedError(f"проект {payload.slug} не удалось ни найти, ни создать") from None
        else:
            print(f"проект создан: {project.slug} ({project.id})")
            return project

    changed = False
    if project.name != payload.name:
        project.name = payload.name
        changed = True
    if project.repo_url != payload.repo_url:
        project.repo_url = payload.repo_url
        changed = True
    if project.default_branch != payload.default_branch:
        project.default_branch = payload.default_branch
        changed = True
    if changed:
        session.commit()
        print(f"проект обновлён: {project.slug} ({project.id})")
    else:
        print(f"проект найден: {project.slug} ({project.id})")
    _ensure_membership(session, project, user)
    return project


def _active_tokens(session: Session, project: Project, name: str) -> list[ProjectToken]:
    """Действующие токены проекта с указанным именем."""
    statement = select(ProjectToken).where(
        ProjectToken.project_id == project.id,
        ProjectToken.name == name,
        ProjectToken.revoked_at.is_(None),
    )
    return list(session.scalars(statement))


def _ensure_token(session: Session, project: Project, name: str, rotate: bool) -> str | None:
    """Возвращает открытое значение нового токена или `None`, если он уже есть."""
    active = _active_tokens(session, project, name)
    if active and not rotate:
        print(
            f"токен «{name}» уже действует; открытое значение не хранится. "
            "Новый можно выпустить с --rotate-token"
        )
        return None
    for stored in active:
        revoke_token(session, project.id, stored.id)
        print(f"токен отозван: {stored.name} ({stored.id})")

    token, stored = create_token(session, project.id, name)
    print(f"токен создан: {stored.name} ({stored.id})")
    return token


def _baseline_scan(session: Session, project: Project, args: argparse.Namespace) -> Scan | None:
    """Прогон для baseline: указанный или последний завершённый."""
    if args.baseline_scan is not None:
        scan = session.get(Scan, args.baseline_scan)
        if scan is None or scan.project_id != project.id:
            raise SeedError(f"прогон {args.baseline_scan} не найден в проекте {project.slug}")
        return scan

    if args.baseline_latest:
        statement = (
            select(Scan)
            .where(Scan.project_id == project.id, Scan.status == ScanStatus.DONE.value)
            .order_by(Scan.created_at.desc(), Scan.id.desc())
            .limit(1)
        )
        scan = session.scalar(statement)
        if scan is None:
            raise SeedError(
                f"у проекта {project.slug} нет завершённых прогонов: "
                "сначала запустите проверку и дождитесь done"
            )
        return scan

    return None


def _apply_baseline(session: Session, project: Project, args: argparse.Namespace) -> None:
    """Ставит baseline по выбранному прогону; без флагов ничего не делает."""
    scan = _baseline_scan(session, project, args)
    if scan is None:
        return
    try:
        baseline = install_baseline(session, scan)
    except BaselineError as error:
        raise SeedError(str(error)) from error
    print(
        f"baseline установлен по прогону {baseline.scan_id}; "
        "находки этого прогона больше не блокируют вердикт"
    )


def _seed_engine() -> Engine:
    """Движок из `DATABASE_URL` с конечным таймаутом подключения."""
    url = make_url(database_url())
    if "connect_timeout" not in url.query:
        url = url.update_query_dict({"connect_timeout": str(CONNECT_TIMEOUT_SEC)})
    return build_engine(url.render_as_string(hide_password=False))


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Флаги baseline: взаимоисключающие, по умолчанию baseline не меняется."""
    parser = argparse.ArgumentParser(
        prog="seed_demo",
        description="Создаёт демо-пользователя, проект и токен Patches, Please.",
    )
    parser.add_argument(
        "--rotate-token",
        action="store_true",
        help="отозвать действующие токены с тем же именем и выпустить новый",
    )
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument(
        "--baseline-latest",
        action="store_true",
        help="зафиксировать baseline по последнему завершённому прогону проекта",
    )
    baseline.add_argument(
        "--baseline-scan",
        metavar="UUID",
        type=uuid.UUID,
        help="зафиксировать baseline по указанному прогону",
    )
    return parser.parse_args(argv)


def _seed(args: argparse.Namespace) -> None:
    """Один проход: пользователь, проект, токен, при необходимости baseline."""
    email = _env("DEMO_EMAIL", DEFAULT_EMAIL)
    password = _password_from_env()
    payload = _project_payload()
    token_name = _env("DEMO_TOKEN_NAME", DEFAULT_TOKEN_NAME)

    engine = _seed_engine()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        with factory() as session:
            user = _ensure_user(session, email, password)
            project = _ensure_project(session, payload, user)
            token = _ensure_token(session, project, token_name, args.rotate_token)
            _apply_baseline(session, project, args)
            project_id = project.id
    finally:
        engine.dispose()

    print()
    print(f"демо-стенд готов: пользователь {email}, проект {payload.slug} ({project_id})")
    if token is not None:
        print(f"токен проекта (показывается один раз): {token}")
    print("дальше: запустите прогон по коммиту демо-репозитория — см. docs/demo.md")


def main(argv: list[str] | None = None) -> int:
    """Точка входа: параметры, наполнение стенда и код возврата."""
    args = _parse_args(argv)
    try:
        _seed(args)
    except SeedError as error:
        print(f"Наполнение не выполнено: {error}", file=sys.stderr)
        return 1
    except SQLAlchemyError as error:
        print(f"Наполнение не выполнено: {error}", file=sys.stderr)
        print(
            "Проверьте DATABASE_URL, запущен ли PostgreSQL и применены ли миграции "
            "(uv run alembic upgrade head).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
