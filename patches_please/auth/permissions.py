"""Права на проект: одна проверка для API и страниц (T-025, FR-017, FR-018).

`project_members` — единственное основание видеть проект. Отсюда берут проверку
и REST API, и HTML-страницы: правила одни, отличаются только коды ответа.

- Участник (`owner` или `member`) видит данные проекта.
- Управляют токенами, политикой и исключениями только владельцы (`owner`);
  участник получает 403: проект ему известен, скрывать нечего.
- Посторонний на странице получает 403, в API — 404: по угаданному UUID
  существование чужого проекта не раскрывается. В обоих случаях тело ответа
  не содержит названия проекта, slug, коммита, правил и причин исключений.

Проверка не пишет в базу и не меняет проект: она только отвечает на вопрос
«можно ли», поэтому её одинаково вызывают и из API, и из страниц.
"""

import uuid
from typing import Final

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from patches_please.auth.models import User
from patches_please.projects.models import OWNER_ROLE, ProjectMember

# Одно сообщение на все закрытые методы API: что именно за проект, не раскрывается.
PROJECT_NOT_FOUND_MESSAGE: Final = "Проект не найден"
# Участнику API сообщает, что прав не хватает, а не что проекта нет.
FORBIDDEN_MESSAGE: Final = "Недостаточно прав"
# Страница отвечает 403: slug и так виден в адресе, но данных проекта в теле нет.
PROJECT_FORBIDDEN_MESSAGE: Final = "Нет доступа к проекту"


def project_role(session: Session, project_id: uuid.UUID, user_id: uuid.UUID) -> str | None:
    """Роль пользователя в проекте; `None` — проекта нет или он не участник."""
    return session.scalar(
        select(ProjectMember.role).where(
            ProjectMember.project_id == project_id,
            ProjectMember.user_id == user_id,
        )
    )


def is_project_member(session: Session, project_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """Строка членства — единственное основание видеть проект (FR-017, FR-018)."""
    statement = select(ProjectMember.project_id).where(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == user_id,
    )
    return session.scalar(statement) is not None


def require_project_member(
    session: Session,
    project_id: uuid.UUID,
    user: User,
    *,
    hide_project: bool = False,
) -> None:
    """Пропускает любого участника проекта.

    Посторонний на странице получает 403: проект известен из адреса, но данных
    в ответе нет. `hide_project=True` — 404, как в API: существование чужого
    проекта по угаданному идентификатору не раскрывается.
    """
    if is_project_member(session, project_id, user.id):
        return
    if hide_project:
        # Несуществующий и чужой проект выглядят одинаково: данные не отдаём.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=PROJECT_NOT_FOUND_MESSAGE)
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=PROJECT_FORBIDDEN_MESSAGE)


def require_project_owner(session: Session, project_id: uuid.UUID, user: User) -> None:
    """Пропускает только владельца проекта. Посторонний видит 404, участник — 403."""
    role = project_role(session, project_id, user.id)
    if role is None:
        # Несуществующий и чужой проект выглядят одинаково: данные проекта не отдаём.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=PROJECT_NOT_FOUND_MESSAGE)
    if role != OWNER_ROLE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=FORBIDDEN_MESSAGE)
