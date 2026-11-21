"""Токены проектов: генерация, хеш, создание, список, отзыв, проверка (T-006).

Открытое значение токена живёт только в ответе на создание: `create_token`
возвращает его отдельно от модели, а в `project_tokens` пишется SHA-256 —
та же функция `token_hash`, что у cookie-сессии, потому что значение
высокоэнтропийное и медленный хеш с солью ничего не добавит к защите.

Функции, меняющие данные, сами фиксируют изменения (`commit`): вызывающему
коду — роутерам и тестам — не нужно помнить про границы транзакции.
"""

import secrets
import uuid
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.service import token_hash
from app.tokens.models import ProjectToken

# Префикс отличает токен Security Gate от прочих строк, если он попадёт в вывод.
TOKEN_PREFIX: Final = "sg_"
# 32 байта энтропии: token_urlsafe даёт 43 символа, вместе с префиксом — 46.
TOKEN_ENTROPY_BYTES: Final = 32


def generate_token() -> str:
    """Новый токен: префикс и случайная часть. Открытое значение не сохраняется."""
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_ENTROPY_BYTES)


def create_token(session: Session, project_id: uuid.UUID, name: str) -> tuple[str, ProjectToken]:
    """Создаёт токен и возвращает открытое значение вместе со строкой БД.

    Открытое значение возвращается вызывающему один раз: в модели его нет,
    поэтому повторно получить его из базы нельзя. `IntegrityError` не ловится:
    единственное уникальное поле — SHA-256, а коллизия на 32 байтах энтропии
    практически невозможна.
    """
    token = generate_token()
    stored = ProjectToken(project_id=project_id, name=name, token_hash=token_hash(token))
    session.add(stored)
    session.commit()
    # id и created_at выставляет PostgreSQL, поэтому читаем строку обратно.
    session.refresh(stored)
    return token, stored


def list_tokens(session: Session, project_id: uuid.UUID) -> list[ProjectToken]:
    """Токены проекта: свежие сверху, при равенстве времени — по названию."""
    statement = (
        select(ProjectToken)
        .where(ProjectToken.project_id == project_id)
        .order_by(ProjectToken.created_at.desc(), ProjectToken.name)
    )
    return list(session.scalars(statement))


def revoke_token(session: Session, project_id: uuid.UUID, token_id: uuid.UUID) -> bool:
    """Помечает токен недействительным. `False` — такого токена в проекте нет.

    Отзыв идемпотентен: у уже отозванного токена `revoked_at` не перезаписывается,
    чтобы в истории осталось время первого отзыва. Строка читается с блокировкой
    (`FOR UPDATE`): два одновременных запроса не разойдутся в проверке и не
    запишут разное время.
    """
    stored = session.scalar(
        select(ProjectToken)
        .where(
            ProjectToken.id == token_id,
            ProjectToken.project_id == project_id,
        )
        .with_for_update()
    )
    if stored is None:
        return False
    if stored.revoked_at is None:
        stored.revoked_at = datetime.now(UTC)
        session.commit()
    return True


def verify_token(session: Session, token: str) -> ProjectToken | None:
    """Действующий токен по открытому значению; отозванный и неизвестный — `None`.

    Успешная проверка обновляет `last_used_at`: по нему видно, каким токеном
    CI пользовался в последний раз. Хеш сравнивается поиском по уникальному
    индексу: значение высокоэнтропийное, поэтому соль и медленный хеш не нужны.
    """
    stored = session.scalar(
        select(ProjectToken).where(ProjectToken.token_hash == token_hash(token))
    )
    if stored is None or stored.revoked_at is not None:
        return None
    stored.last_used_at = datetime.now(UTC)
    session.commit()
    return stored
