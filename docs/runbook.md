# Runbook: развёртывание Patches, Please с нуля

Инструкция для T-033 (NFR-006, CON-004): как поднять стенд Patches, Please на
чистой машине, проверить его и получить первый прогон. Рассчитана на человека,
который видит проект впервые: каждая команда дана с ожидаемым результатом и
кодом возврата.

## Что должно получиться

`docker compose` поднимает четыре сервиса на одной машине:

| Сервис | Образ | Роль | Порт |
| --- | --- | --- | --- |
| `postgres` | `postgres:16-alpine` | схема БД, история прогонов | `5432` |
| `redis` | `redis:7.2-alpine` | очередь RQ | не публикуется |
| `api` | `patches-please-api:local` | REST API, страницы, `/health` | `8000` |
| `worker` | `patches-please-worker:local` | очередь, клон репозитория, три сканера, отчёты | не публикуется |

После развёртывания доступны:

- `http://localhost:8000/health` — healthcheck сервиса;
- `http://localhost:8000/login` — вход в интерфейс;
- `http://localhost:8000/docs` — интерактивная схема API.

Цель NFR-006 — уложиться в 30 минут от чистой машины до работающего стенда.
Фактический замер — в разделе «Хронометраж».

## Предусловия

| Что | Требование | Как проверить |
| --- | --- | --- |
| ОС | Windows 10/11 x64 с WSL2, macOS 13+, Linux x64/arm64 | — |
| Виртуализация | включена в BIOS/UEFI (для Docker Desktop) | Windows: Диспетчер задач → Производительность → «Виртуализация: включена» |
| Docker | Docker Desktop (Windows, macOS) актуальной версии, проверено на 29.0.1; на Linux — Docker Engine с плагином Compose | `docker version`, `docker compose version` |
| `uv` | 0.13 или новее (проверено на 0.13.9) | `uv --version` |
| `git` | любая актуальная версия | `git --version` |
| Порты | `8000` и `5432` свободны | `netstat -ano \| findstr :8000` (Windows) |
| Сеть | при первой сборке нужны `ghcr.io`, `pypi.org`, `github.com` и хранилище базы Trivy; после сборки сканеры работают офлайн | — |
| Права | установка Docker Desktop и запуск его службы требуют прав администратора | — |
| Место на диске | с запасом под два образа, тома PostgreSQL/Redis и каталог отчётов | — |

`docker version` считается успешным, только если в выводе есть и `Client:`, и
`Server:`. Один `Client:` без `Server:` означает, что движок не запущен, — идти
дальше нельзя.

## Шаг 1. Получить репозиторий

```bash
git clone https://github.com/arslan-ahmetjanov/patches-please.git
cd patches-please
```

Ожидаемо: код возврата `0`, в каталоге появились `docker-compose.yml`,
`Dockerfile`, `Dockerfile.worker`, `pyproject.toml`.

## Шаг 2. Установить `uv`

Windows, PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

macOS, Linux:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Откройте новый терминал и проверьте:

```bash
uv --version
```

Ожидаемо: строка вида `uv 0.13.9` (версия может быть новее), код возврата `0`.

Затем поставьте зависимости проекта:

```bash
uv sync
```

`uv` сам скачает Python 3.12 по `.python-version` и создаст `.venv`. Код
возврата `0`. Этот шаг нужен для команд с хоста — миграций, заполнения демо-данных,
CLI и тестов; сам стек Docker работает и без него.

## Шаг 3. Запустить Docker Desktop

1. Запустите Docker Desktop (Windows: «Пуск» → Docker Desktop).
2. Дождитесь состояния «Engine running»: значок кита в трее перестал мигать.
3. Проверьте движок:

```bash
docker version
docker compose version
```

Ожидаемо: в `docker version` заполнены разделы `Client` и `Server`; `docker
compose version` печатает версию плагина, код возврата `0`.

Если `docker version` заканчивается ошибкой вида `failed to connect to the docker
API ... dockerDesktopLinuxEngine`, движок не поднят. На Windows служба
`com.docker.service` запускается только с правами администратора: откройте
терминал «Запуск от имени администратора» и выполните `sc start com.docker.service`.
Ошибка `5` («Отказано в доступе») означает, что прав не хватило, — см.
«Устранение неполадок».

## Шаг 4. Настроить `.env`

```bash
cp .env.example .env
```

PowerShell:

```powershell
Copy-Item .env.example .env
```

Ожидаемо: в каталоге появился файл `.env`, код возврата `0`. Файл `.env` не
коммитится и в образ не копируется. Переменные:

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `APP_ENV` | `local` | `local` — стенд по HTTP; любое другое значение включает `Secure` у cookie сессии и CSRF, то есть требует HTTPS |
| `API_PORT` | `8000` | порт API на хосте |
| `POSTGRES_USER` | `patches_please` | пользователь БД |
| `POSTGRES_PASSWORD` | `patches_please_local` | пароль БД; для демо-стенда и защиты смените |
| `POSTGRES_DB` | `patches_please` | имя базы |
| `POSTGRES_PORT` | `5432` | порт PostgreSQL на хосте |
| `DATABASE_URL` | `postgresql+psycopg://…@postgres:5432/patches_please` | строка подключения **для контейнеров**; хост `postgres` — имя сервиса Compose |
| `REDIS_URL` | `redis://redis:6379/0` | очередь **для контейнеров** |
| `REPORTS_DIR` | `/app/reports` | каталог отчётов внутри worker; том `reportsdata` |

Если меняете `POSTGRES_PASSWORD` или `POSTGRES_PORT`, поменяйте их и в
`DATABASE_URL` — иначе контейнеры не подключатся к базе. При смене
`POSTGRES_PORT` миграции с хоста тоже требуют явного `DATABASE_URL` (шаг 7).

`DATABASE_URL` из `.env` указывает на хост `postgres`, которого нет на хостовой
машине. Не экспортируйте его в оболочку хоста: для команд с хоста нужен
`localhost` (значение по умолчанию в `patches_please/db.py`).

## Шаг 5. Собрать и запустить стек

```bash
docker compose up -d --build
```

Что происходит при первой сборке:

- `api` — установка зависимостей из `uv.lock` в образ на базе
  `ghcr.io/astral-sh/uv:python3.12-bookworm-slim`;
- `worker` — тот же базовый образ плюс Semgrep из PyPI, Gitleaks и Trivy с
  GitHub (скачивание сверяется по SHA256) и база уязвимостей Trivy;
- `postgres` и `redis` — готовые образы, запускаются с healthcheck-ами;
- `api` и `worker` стартуют только после того, как база и Redis признаны
  здоровыми.

Ожидаемо: код возврата `0`, в конце вывода — строки `Started` или `Running`
для четырёх контейнеров (`Container patches-please-… Started`).

Сборка образов — единственный шаг, которому нужна сеть: зависимости `api`,
версии сканеров и база Trivy зашиваются в образ (`docs/scanners.md`). Повторная
сборка использует кеш слоёв и проходит быстрее.

## Шаг 6. Проверить контейнеры и API

```bash
docker compose ps
curl http://localhost:8000/health
```

PowerShell вместо `curl`:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

Ожидаемо:

- `docker compose ps` — четыре строки, у всех состояние `Up`, у `api`, `worker`,
  `postgres` и `redis` в скобках `(healthy)`;
- `/health` — HTTP 200 и тело `{"status":"ok"}`; `curl` возвращает код `0`.

Healthcheck-и стартуют не сразу: у `postgres` и `api` `start_period` 10 секунд,
у `worker` — 15. Если статус `starting`, подождите до минуты и повторите.

## Шаг 7. Применить миграции

```bash
uv run alembic upgrade head
```

Ожидаемо: семь строк `Running upgrade …`, последняя — `0007`; код возврата
`0`. Повторный запуск ничего не делает и завершается с кодом `0`.

Проверка, что модели и схема не разошлись:

```bash
uv run alembic check
```

Ожидаемо: `No new upgrade operations detected.`, код возврата `0`.

Миграции с хоста по умолчанию идут на `localhost:5432` (значение из
`patches_please/db.py`). Если `POSTGRES_PORT` в `.env` изменён, задайте
`DATABASE_URL` явно:

```bash
# bash, Git Bash, WSL
DATABASE_URL=postgresql+psycopg://patches_please:пароль@localhost:5433/patches_please \
  uv run alembic upgrade head
```

```powershell
# PowerShell
$env:DATABASE_URL = "postgresql+psycopg://patches_please:пароль@localhost:5433/patches_please"
uv run alembic upgrade head
```

API миграции при старте не применяет: без этого шага страницы вернут ошибку
обращения к несуществующим таблицам.

## Шаг 8. Создать первого пользователя и демо-данные

Регистрации в интерфейсе нет, поэтому учётную запись создаёт скрипт
`scripts/seed_demo.py`. Он идемпотентен: создаёт пользователя, проект и токен CI
либо приводит существующие записи к значениям из окружения. Подробности и
установка baseline — в `docs/demo.md`.

```bash
export DEMO_PASSWORD='<пароль не короче 8 символов>'
export DEMO_REPO_URL='https://github.com/arslan-ahmetjanov/patches-please-demo.git'
uv run python scripts/seed_demo.py
```

PowerShell:

```powershell
$env:DEMO_PASSWORD = "<пароль не короче 8 символов>"
$env:DEMO_REPO_URL = "https://github.com/arslan-ahmetjanov/patches-please-demo.git"
uv run python scripts/seed_demo.py
```

Ожидаемо: код возврата `0`, вывод вида

```text
пользователь создан: demo@example.com
проект создан: patches-please-demo (<uuid>)
токен создан: ci (<uuid>)

демо-стенд готов: пользователь demo@example.com, проект patches-please-demo (<uuid>)
токен проекта (показывается один раз): pp_…
```

Токен печатается один раз: в базе хранится только SHA-256. Сохраните значение —
оно нужно для запуска прогона. Код возврата `1` означает ошибку параметров,
подключения или baseline; сообщение печатается в stderr.

Демо-репозиторий должен быть публичным: worker клонирует его без учётных
данных. Если демо не нужно, тот же скрипт создаёт пользователя, проект и токен
по вашему репозиторию; без него войти в интерфейс не получится.

## Шаг 9. Проверить интерфейс и прогон

1. Откройте `http://localhost:8000/login`.
2. Войдите с email `demo@example.com` (или `DEMO_EMAIL`) и паролем из
   `DEMO_PASSWORD`.
3. Ожидаемо: редирект на `/projects`, в списке — проект `patches-please-demo`.

Полная проверка прогона через CLI (токен из шага 8):

```bash
export PATCHES_PLEASE_TOKEN='pp_…'
uv run patches-please scan \
  --provider github \
  --commit <полный SHA коммита демо-репозитория> \
  --ref main \
  --wait
```

Коды возврата CLI: `0` — `pass`, `1` — `fail`, `2` — ошибка аргументов, `3` — нет
доступа, `4` — прогон завершился `error`, `5` — истёк таймаут, `6` — сеть.
Первый прогон на демо-репозитории ожидаемо завершается кодом `1`: политика по
умолчанию блокирует `critical` и `high`, а высокие находки Trivy новые. Это не
ошибка настройки — см. `docs/demo.md`.

## Шаг 10. Остановка, обновление, удаление

```bash
docker compose stop              # остановить, данные сохранить
docker compose down              # удалить контейнеры, тома сохранить
docker compose down -v           # удалить контейнеры и тома: БД, Redis, отчёты
docker compose logs -f --tail=100 api worker
```

Обновление после `git pull`:

```bash
docker compose up -d --build
uv run alembic upgrade head
```

Резервная копия базы и восстановление (пользователь и база — из `POSTGRES_USER`
и `POSTGRES_DB`):

```bash
docker compose exec -T postgres pg_dump -U patches_please patches_please > backup.sql
docker compose exec -T postgres psql -U patches_please patches_please < backup.sql
```

## Хронометраж

Замер по этой инструкции. Цель NFR-006 — не более 30 минут.

### Методика

1. Исходное состояние: `uv` 0.13.9 и Docker Desktop 29.0.1 установлены, движок
   запущен. Это предусловия инструкции, поэтому их установка в замер не входит.
2. Стенд приведён к виду «как с чистой машины»: `docker compose down -v`
   (контейнеры, сеть и тома), удалены образы `patches-please-api:local` и
   `patches-please-worker:local`, очищен кеш сборки (`docker builder prune -af`,
   14.93 ГБ), удалён `.venv`, очищен кеш пакетов `uv` (`uv cache clean`, 863 МиБ).
3. Секундомер — от копирования `.env` до успешного входа в интерфейс. Каждый шаг
   засекался отдельно, итог — сумма шагов; время до ответа `/health` считается
   отдельно, потому что это критерий NFR-006.
4. Сеть — обычная рабочая, без прокси и VPN.
5. Публикация демо-репозитория не входит: это T-032, адрес репозитория уже
   существовал.

### Результат

**Итог: 351.3 с (5 мин 51 с) при пороге 30 минут.**

Дата: 2026-11-25, локальное время (UTC+05:00).

| Что | Значение |
| --- | --- |
| Машина | HUAWEI RLEF-XX, Windows 11 Pro 10.0.26300 |
| Процессор | Intel Core i5-12500H, 12 ядер / 16 потоков |
| ОЗУ хоста | 16 111 МБ (16 ГБ) |
| Docker | Docker Desktop 29.0.1, Compose v2.40.3-desktop.1, ядро WSL2 |
| `uv` | 0.13.9 |
| Стенд | `postgres:16-alpine`, `redis:7.2-alpine`, `patches-please-api:local`, `patches-please-worker:local` |
| Размер образов | `api` — 503 МБ на диске (120 МБ контента), `worker` — 3.82 ГБ (552 МБ контента) |
| Адрес API | `http://localhost:8081` — порт 8000 на этой машине попадает в зарезервированный диапазон Windows 7979–8078; на обычном стенде — 8000 |

| Шаг | Что засекалось | Время |
| --- | --- | ---: |
| 4 | копирование `.env` | < 0.1 с |
| 2 | `uv sync` с пустым кешем `uv` и без `.venv` | 23.9 с |
| 5 | `docker compose up -d --build` | 318.5 с |
| 6 | ожидание `/health` до `{"status":"ok"}` | 2.5 с |
| 7 | `uv run alembic upgrade head` | 3.8 с |
| 8 | создание пользователя и демо-данных | 2.2 с |
| 9 | вход в интерфейс и страница `/projects` | 0.2 с |
| Итог до `/health` | шаги 4–6 | 344.9 с (5 мин 45 с) |
| Итог | шаги 4–9 | 351.3 с (5 мин 51 с) |

Что было холодным: образы проекта, кеш сборки, `.venv`, кеш пакетов `uv`, тома
PostgreSQL/Redis/отчётов. При сборке скачивался `redis:7.2-alpine`; из базовых
образов в локальном кеше был только `postgres:16-alpine`. Скачивание базового
образа для `api`/`worker` и установка Semgrep, Gitleaks, Trivy и базы Trivy
входят в 318.5 с.

Что осталось тёплым: сам `uv`, Python 3.12, установленный `uv` ранее, и образ
`postgres:16-alpine`.

Вывод: NFR-006 выполнен с запасом примерно в пять раз — 5 мин 51 с против
30 минут. Основное время занимает первая сборка образов (91 % итога); повторное
развёртывание с кешем слоёв идёт заметно быстрее.

Ограничения замера:

- Это не чистая установка ОС: `uv` и Docker Desktop уже стояли, Python 3.12 и
  `postgres:16-alpine` были в локальном кеше. Остальные шаги выполнялись с нуля,
  как на новой машине.
- Замер один, а не серия из трёх: разброс даёт в основном скорость сети при
  скачивании образов и пакетов.
- Docker Desktop на этой машине останавливал движок при простое; на время
  замера он работал, перезапуски в итог не входят. На стенде с постоянно
  запущенным движком поведение то же.
- Порт 8081 — следствие ограничения Windows на этой машине, а не часть
  инструкции.
- Время указано для сети без прокси и VPN. При медленном канале первая сборка
  займёт больше.

## Устранение неполадок

| Симптом | Причина | Что делать |
| --- | --- | --- |
| `docker version`: `failed to connect to the docker API … npipe` (Windows) | Docker Desktop не запущен или служба остановлена | Запустить Docker Desktop; при ошибке службы — `sc start com.docker.service` из терминала от имени администратора |
| `sc start com.docker.service`: ошибка `5` | нет прав администратора | Запустить терминал «От имени администратора»; если политика запрещает — обратиться к администратору машины |
| Docker Desktop не стартует, `wsl --status` с ошибкой | не установлен или устарел WSL2 | `wsl --install`, `wsl --update`, перезагрузка |
| `bind: address already in use` для `5432` | локальный PostgreSQL занимает порт | Указать `POSTGRES_PORT=5433` в `.env`; для миграций задать `DATABASE_URL` с `localhost:5433` |
| `bind: address already in use` для `8000`, хотя порт свободен | порт попал в зарезервированный диапазон Windows | `netsh interface ipv4 show excludedportrange protocol=tcp`; задать `API_PORT=8081` |
| `api` в состоянии `unhealthy`, в логах `connection refused` к `postgres` | база ещё не готова или пароль не совпадает с `DATABASE_URL` | Подождать `start_period`; сверить `POSTGRES_PASSWORD` и пароль в `DATABASE_URL`; `docker compose logs postgres` |
| `worker` в состоянии `unhealthy` | воркер не зарегистрировался в очереди | `docker compose logs worker`; проверить `REDIS_URL` и `docker compose ps redis` |
| `alembic upgrade head`: `password authentication failed` | в оболочке экспортирован `DATABASE_URL` из `.env` с хостом `postgres` | Убрать переменную из окружения или задать строку с `localhost` |
| `alembic upgrade head`: `connection refused` | PostgreSQL не запущен или порт другой | `docker compose ps postgres`; сверить `POSTGRES_PORT` |
| `docker compose build`: `curl: (22)` или несовпадение SHA256 | нет доступа к GitHub Releases или прокси подменяет ответ | Проверить сеть и прокси Docker; повторить сборку |
| `docker compose build`: ошибка установки Semgrep | нет доступа к PyPI | Проверить прокси и `docker info`; повторить |
| `no space left on device` | закончилось место под образы и тома | `docker system df`, затем `docker system prune` (удаляет неиспользуемое) |
| `/health` отвечает, страницы — 500 | не применены миграции | Выполнить шаг 7 |
| Вход: 401 при верном пароле | пользователь не создан или пароль другой | Повторить шаг 8 с нужным `DEMO_PASSWORD` |
| Прогон долго в `queued` | worker не запущен или упал | `docker compose ps worker`, `docker compose logs worker` |
| Прогон `error`, в причине клонирование | репозиторий приватный или адрес неверный | Указать публичный HTTPS-адрес в `repo_url` |
| Вход не сохраняется, cookie не приходит по HTTP | `APP_ENV` не `local`, поэтому cookie помечена `Secure` | Для стенда по HTTP вернуть `APP_ENV=local`; для HTTPS задать `APP_ENV` с любым другим значением |

## Ограничения

- Развёртывание описано для Docker Compose на одной машине. Кластера,
  балансировки и внешнего PostgreSQL инструкция не покрывает.
- Сканеры работают офлайн, но клон репозитория проекта идёт по сети: без
  доступа к репозиторию прогон завершится `error`. NFR-003 относится к работе
  сканеров, а не к клонированию.
- База уязвимостей Trivy зашита в образ при сборке и между пересборками не
  обновляется: свежесть базы — это пересборка `worker`
  (`docs/scanners.md`).
- Набор правил Semgrep минимальный и лежит в репозитории; реестр `p/...` в
  офлайне недоступен.
- Отчёты прогонов лежат файлами в томе `reportsdata` (`REPORTS_DIR`); метода API
  для их скачивания нет.
- Регистрации нет: учётные записи создаются скриптом или сервисной функцией.
- `Secure` у cookie включается при `APP_ENV`, отличном от `local`; без HTTPS
  вход в этом режиме не работает.
- Пароль PostgreSQL по умолчанию — только для локального стенда. Перед показом
  смените его в `.env`.

## Связанные документы

- `README.md` — краткое описание и быстрый старт.
- `docs/demo.md` — демо-репозиторий, baseline и ожидаемые находки.
- `docs/scanners.md` — состав образа worker, офлайн-режим и обновление сканеров.
- `docs/measurements.md` — замеры NFR-001 и NFR-002.
- `specs/patches-please-mvp/spec.md` — NFR-003, NFR-006, CON-004.
