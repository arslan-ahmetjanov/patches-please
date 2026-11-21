# Security Gate

Информационная система автоматизированного контроля безопасности разработки (Security Gate) для CI/CD-конвейера.

Дипломный проект — ВКР по направлению 09.03.03 «Прикладная информатика», УГНТУ.

## Что делает система

Встраивается в пайплайн, запускает проверки безопасности (SAST, секреты, уязвимые зависимости и образы), приводит результаты к единой модели, применяет политику проекта и блокирует переход релиза на следующий этап при критических находках. Ведёт историю прогонов и показывает метрики.

## Источник темы

Тема взята из открытого запроса корпорации на площадка пилотных запросов: «Автоматизированная система контроля безопасности разработки (Security Gate)», заказчик — страховая компания. Карточка запроса, цитата и маппинг на требования — в `docs/source-request.md`.

## Статус

Спецификация V1 зафиксирована. Реализация идёт по этапам `specs/security-gate-mvp/tasks.md`: выполнен этап 1 — скелет проекта (T-001), из этапа 2 закрыто подключение к PostgreSQL и первая миграция (T-002).

## Быстрый старт

Нужны Docker Compose и [uv](https://docs.astral.sh/uv/).

```bash
uv sync                        # зависимости для локальных тестов и линта
cp .env.example .env           # параметры локального стенда
docker compose up -d --build   # postgres, redis, api, worker
curl http://localhost:8000/health
```

Ожидаемый ответ: `{"status":"ok"}`. Остановка стека — `docker compose down`.
Подробный runbook развёртывания с нуля появится в задаче T-033.

## База данных и миграции

Схема хранится в PostgreSQL 16, изменения — в миграциях Alembic. Строка подключения
одна на всё: переменная `DATABASE_URL`. Контейнеры `api` и `worker` получают её из
`docker-compose.yml` (хост `postgres`), а миграции с хоста запускаются без переменной
и по умолчанию идут на `localhost:5432` — значение задано в `app/db.py`.

Если меняли пароль или порт PostgreSQL в `.env`, передайте `DATABASE_URL` и при
миграциях с хоста:

```bash
# bash, Git Bash, WSL
DATABASE_URL=postgresql+psycopg://security_gate:пароль@localhost:5432/security_gate \
  uv run alembic upgrade head
```

```powershell
# PowerShell
$env:DATABASE_URL = "postgresql+psycopg://security_gate:пароль@localhost:5432/security_gate"
uv run alembic upgrade head
```

Команды:

```bash
docker compose up -d          # PostgreSQL должна быть запущена и здорова
uv run alembic upgrade head   # применить все миграции
uv run alembic downgrade -1   # откатить одну миграцию
uv run alembic check          # модели и схема БД не расходятся
```

Первая миграция `migrations/versions/0001_users_sessions.py` создаёт таблицы `users`
и `sessions` по разделу «Данные и контракты» плана. Проверки: `tests/test_migrations.py`
прогоняет upgrade и downgrade без базы (Alembic генерирует SQL в офлайн-режиме),
`tests/test_db.py` — интеграционный тест, ему нужен поднятый стек и применённые миграции.

Комментарии в `alembic.ini` оставлены на английском намеренно: Alembic читает файл
в кодировке системы, и кириллица ломает миграции на Windows.

## Разработка

```bash
uv run pytest -m "not integration"
uv run ruff check .
uv run mypy app
```

Интеграционные тесты (`pytest -m integration`) требуют запущенного стека и
применённых миграций.

## Структура

```
app/                      # api, worker, scanners, normalize, policy, reports, web
alembic.ini               # конфигурация Alembic
migrations/               # миграции схемы БД
contracts/openapi.yaml    # контракт REST API
specs/
  security-gate-mvp/
    spec.md     # что и зачем, сценарии, требования, критерии приёмки
    plan.md     # архитектура, стек, данные, контракты, риски
    tasks.md    # задачи с трассировкой к требованиям
tests/                    # pytest
```

Реализация начинается с `tasks.md`: одна задача — один коммит, проверка указана в задаче.

## Процесс

Разработка ведётся по SDD: спецификация — источник правды, код — её следствие. Изменение поведения начинается с правки спецификации.

## Лицензия

Учебный проект. Лицензия будет определена после согласования с вузом.
