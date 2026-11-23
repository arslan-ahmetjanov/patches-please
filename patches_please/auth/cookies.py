"""Атрибуты cookie сессии и CSRF-токена (T-024).

Локальный стенд работает по HTTP, и браузер не вернул бы `Secure`-cookie:
поэтому флаг включается только вне локального окружения. Пустое значение
`APP_ENV` считается локальным — так запуск без `.env` и тесты ведут себя как
стенд. Демо-стенд за HTTPS ставит `APP_ENV=demo`, и обе cookie получают
`Secure`. Отдельная переменная не нужна: окружение уже задаёт режим стенда.
"""

import os
from typing import Final

# Значение `APP_ENV`, при котором стенд работает по HTTP.
LOCAL_ENV: Final = "local"


def cookies_secure() -> bool:
    """Нужен ли флаг `Secure`: да, если `APP_ENV` задан и это не `local`."""
    return os.environ.get("APP_ENV", "").strip().lower() not in ("", LOCAL_ENV)
