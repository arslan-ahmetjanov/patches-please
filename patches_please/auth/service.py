"""Пароли и сессии браузера (T-004, FR-022, FR-023).

Пароль хранится строкой `scrypt$n$r$p$<соль_hex>$<хеш_hex>`: параметры записаны
в саму строку, поэтому их можно поменять, не ломая существующие учётные записи.
Токен сессии живёт только в cookie, в таблице `sessions` лежит его SHA-256.

Функции сами фиксируют изменения (`commit`): вызывающему коду — роутерам и тестам —
не нужно помнить про границы транзакции.
"""

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Final

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from patches_please.auth.models import User, UserSession

# Имя cookie задаётся здесь, чтобы роутеры и тесты брали одно значение.
SESSION_COOKIE_NAME: Final = "pp_session"
# Срок жизни сессии браузера; max_age cookie считается из него же.
SESSION_LIFETIME: Final = timedelta(days=7)

SCRYPT_ALGORITHM: Final = "scrypt"
SCRYPT_N: Final = 2**14
SCRYPT_R: Final = 8
SCRYPT_P: Final = 1
SCRYPT_DKLEN: Final = 32
SALT_BYTES: Final = 16
# Минимум памяти для scrypt: OpenSSL по умолчанию держит лимит в 32 МиБ и падает
# на границе, если параметры подросли.
SCRYPT_MIN_MAXMEM: Final = 32 * 1024 * 1024
# Верхняя граница n при проверке: подделанный хеш не должен заказывать гигабайты памяти.
SCRYPT_MAX_N: Final = 2**20


def _scrypt_maxmem(n: int, r: int) -> int:
    """Лимит памяти под конкретные параметры: 128*r*n на блоки плюс два блока запаса."""
    return max(2 * 128 * r * (n + 2), SCRYPT_MIN_MAXMEM)


def hash_password(password: str) -> str:
    """Хеширует пароль scrypt-ом со случайной солью."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=_scrypt_maxmem(SCRYPT_N, SCRYPT_R),
    )
    return f"{SCRYPT_ALGORITHM}${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Сверяет пароль с хешем. Битый или незнакомый формат — `False`, без исключения."""
    parts = password_hash.split("$")
    if len(parts) != 6:
        return False
    algorithm, n_raw, r_raw, p_raw, salt_hex, digest_hex = parts
    if algorithm != SCRYPT_ALGORITHM:
        return False

    try:
        n, r, p = int(n_raw), int(r_raw), int(p_raw)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False

    if not 1 < n <= SCRYPT_MAX_N or n & (n - 1) or r < 1 or p < 1 or not salt or not expected:
        return False

    try:
        actual = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=_scrypt_maxmem(n, r),
        )
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


def create_user(session: Session, email: str, password: str, role: str = "user") -> User:
    """Создаёт учётную запись. В T-004 вызывается только тестами: регистрации нет."""
    user = User(email=email, password_hash=hash_password(password), role=role)
    session.add(user)
    session.commit()
    # id и created_at выставляет PostgreSQL, поэтому читаем строку обратно.
    session.refresh(user)
    return user


@lru_cache(maxsize=1)
def _dummy_password_hash() -> str:
    """Фиктивный хеш для неизвестного email: считается один раз, при первом промахе."""
    return hash_password(secrets.token_urlsafe(32))


def authenticate(session: Session, email: str, password: str) -> User | None:
    """Возвращает пользователя при верной паре email/пароль, иначе `None`."""
    user = session.scalar(select(User).where(User.email == email))
    if user is None:
        # scrypt всё равно считается: иначе неизвестный email отвечает заметно быстрее
        # существующего и по времени ответа видно, заведена ли учётная запись.
        verify_password(password, _dummy_password_hash())
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def token_hash(token: str) -> str:
    """SHA-256 в hex: ровно 64 символа под `sessions.token_hash`."""
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(session: Session, user: User) -> str:
    """Открывает сессию и возвращает токен для cookie. В БД попадает только его хеш."""
    token = secrets.token_urlsafe(32)
    session.add(
        UserSession(
            token_hash=token_hash(token),
            user_id=user.id,
            expires_at=datetime.now(UTC) + SESSION_LIFETIME,
        )
    )
    session.commit()
    return token


def get_session_user(session: Session, token: str) -> User | None:
    """Владелец действующей сессии. Протухшую сессию удаляет и возвращает `None`."""
    stored = session.get(UserSession, token_hash(token))
    if stored is None:
        return None
    if stored.expires_at <= datetime.now(UTC):
        delete_session(session, token)
        return None
    return session.get(User, stored.user_id)


def delete_session(session: Session, token: str) -> None:
    """Закрывает сессию. Отсутствующей строки не требует: выход идемпотентен."""
    session.execute(delete(UserSession).where(UserSession.token_hash == token_hash(token)))
    session.commit()
