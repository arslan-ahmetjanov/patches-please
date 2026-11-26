# Лицензии третьих сторон

Документ закрывает CON-001 и задачу T-031: перечисляет лицензии собственного
кода, сканеров, Python-зависимостей и инфраструктурных образов и фиксирует,
разрешают ли они коммерческое использование. Версии и лицензии проверены
25.11.2026.

Источники версий:

- Python: `uv.lock` и `uv pip list` (48 зависимостей в `uv.lock`; на Windows
  ставится 47, потому что `uvloop` исключён маркером `sys_platform`);
- сканеры: `ARG` в `Dockerfile.worker` и таблица в `docs/scanners.md`;
- образы: `docker-compose.yml`, `Dockerfile`, `Dockerfile.worker`; версии
  внутри образов и digest прочитаны из Docker Hub и GHCR API. Тег `*-alpine`
  плавающий: digest фиксирует состояние на дату проверки, версия внутри образа
  указана по переменным окружения его конфигурации.

Вывод: все компоненты допускают коммерческое использование. Лицензий, которые
запрещают коммерческое использование или не одобрены OSI, в текущем составе
нет. Копилефт-лицензии (LGPL-2.1, LGPL-3.0, MPL-2.0) не распространяются на
код проекта: соответствующие компоненты не модифицируются и не встраиваются в
него.

## Собственный код

| Компонент | Версия | Лицензия | Источник | Коммерческое использование |
| --- | --- | --- | --- | --- |
| Patches, Please (код и документация) | 0.1.0 | MIT | [`LICENSE`](../LICENSE) | Разрешено без ограничений, требуется сохранение уведомления об авторских правах |

## Сканеры

| Сканер | Версия | Лицензия | Источник | Коммерческое использование |
| --- | --- | --- | --- | --- |
| Semgrep | 1.186.0 | LGPL-2.1 | [semgrep/semgrep](https://github.com/semgrep/semgrep/blob/develop/LICENSE) | Разрешено. Копилефт: сканер ставится отдельным окружением `/opt/semgrep`, не модифицируется и запускается отдельным процессом, поэтому код проекта под LGPL не попадает. При распространении образа прилагаются текст лицензии и исходники Semgrep |
| Gitleaks | 8.30.1 | MIT | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks/blob/master/LICENSE) | Разрешено без ограничений |
| Trivy | 0.76.2 | Apache-2.0 | [aquasecurity/trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE) | Разрешено; при распространении образа сохраняются уведомления и `NOTICE` |

Версии закреплены `ARG SEMGREP_VERSION`, `ARG GITLEAKS_VERSION` и
`ARG TRIVY_VERSION` в `Dockerfile.worker`; Gitleaks и Trivy дополнительно
проверяются по SHA256. Зависимости Semgrep ставятся точной версией из PyPI в
отдельное окружение и в `uv.lock` не входят; лицензия самого сканера указана
выше.

## Python-зависимости

### Прямые зависимости

Версии совпадают с `uv.lock` и `uv pip list`.

| Пакет | Версия | Лицензия | Источник | Коммерческое использование |
| --- | --- | --- | --- | --- |
| alembic | 1.20.1 | MIT | [sqlalchemy/alembic](https://github.com/sqlalchemy/alembic) | Разрешено |
| fastapi | 0.165.0 | MIT | [fastapi/fastapi](https://github.com/fastapi/fastapi) | Разрешено |
| httpx | 0.28.1 | BSD-3-Clause | [encode/httpx](https://github.com/encode/httpx) | Разрешено |
| jinja2 | 3.1.6 | BSD-3-Clause | [pallets/jinja](https://github.com/pallets/jinja) | Разрешено |
| psycopg | 3.3.9 | LGPL-3.0-only | [psycopg/psycopg](https://github.com/psycopg/psycopg) | Разрешено. Копилефт: библиотека используется без изменений как динамическая зависимость, код проекта под LGPL не попадает |
| psycopg-binary | 3.3.9 | LGPL-3.0-only | [psycopg/psycopg](https://github.com/psycopg/psycopg) | То же: бинарная сборка `psycopg[binary]`, без изменений |
| python-multipart | 0.0.34 | Apache-2.0 | [Kludex/python-multipart](https://github.com/Kludex/python-multipart) | Разрешено |
| redis (клиент) | 8.1.0 | MIT | [redis/redis-py](https://github.com/redis/redis-py) | Разрешено; лицензия клиента не связана с лицензией сервера Redis |
| rq | 3.0.0 | BSD-2-Clause | [rq/rq](https://github.com/rq/rq) | Разрешено |
| sqlalchemy | 2.1.9 | MIT | [sqlalchemy/sqlalchemy](https://github.com/sqlalchemy/sqlalchemy) | Разрешено |
| uvicorn | 0.54.0 | BSD-3-Clause | [Kludex/uvicorn](https://github.com/Kludex/uvicorn) | Разрешено |

Для `psycopg` (LGPL-3.0) при распространении образа прилагаются текст лицензии
и доступ к исходникам версии 3.3.9: библиотека не модифицируется.

Dev-группа (`[dependency-groups]` в `pyproject.toml`) в поставку не входит:

| Пакет | Версия | Лицензия | Источник | Коммерческое использование |
| --- | --- | --- | --- | --- |
| mypy | 2.4.1 | MIT | [python/mypy](https://github.com/python/mypy) | Разрешено |
| pytest | 9.2.0 | MIT | [pytest-dev/pytest](https://github.com/pytest-dev/pytest) | Разрешено |
| ruff | 0.17.6 | MIT | [astral-sh/ruff](https://github.com/astral-sh/ruff) | Разрешено |

### Транзитивные зависимости

Все 48 зависимостей `uv.lock` по лицензиям. Версии перечислены в `uv.lock`; лицензии взяты из
метаданных соответствующих версий на PyPI. `uvloop` ставится только вне
Windows, поэтому в `uv pip list` на машине проверки его нет.

| Лицензия | Пакетов | Пакеты | Коммерческое использование |
| --- | --- | --- | --- |
| MIT | 25 | alembic, annotated-doc, annotated-types, anyio, ast-serialize, croniter, fastapi, h11, httptools, iniconfig, librt, mako, mypy, mypy-extensions, pluggy, pydantic, pydantic-core, pytest, pyyaml, redis, ruff, sqlalchemy, typing-inspection, uvloop, watchfiles | Разрешено |
| BSD-3-Clause | 12 | click, colorama, httpcore, httpx, idna, jinja2, markupsafe, python-dateutil, python-dotenv, starlette, uvicorn, websockets | Разрешено |
| BSD-2-Clause | 2 | pygments, rq | Разрешено |
| Apache-2.0 | 3 | opentelemetry-api, python-multipart, tzdata | Разрешено |
| Apache-2.0 OR BSD-2-Clause | 1 | packaging | Разрешено по любой из двух |
| MPL-2.0 | 2 | certifi, pathspec | Разрешено. Копилефт на уровне файлов: библиотеки не модифицируются |
| LGPL-3.0-only | 2 | psycopg, psycopg-binary | Разрешено. Копилефт: динамическая зависимость без изменений |
| PSF-2.0 | 1 | typing-extensions | Разрешено |

Все перечисленные лицензии одобрены OSI. Пакетов под GPL, AGPL, SSPL, RSALv2
или проприетарными лицензиями среди Python-зависимостей нет.

## Инфраструктурные образы

| Образ | Версия внутри | Лицензия | Источник | Коммерческое использование |
| --- | --- | --- | --- | --- |
| `postgres:16-alpine` | PostgreSQL 16.16 | PostgreSQL License | [postgres/postgres](https://github.com/postgres/postgres/blob/master/COPYRIGHT) | Разрешено |
| `redis:7.2-alpine` | Redis 7.2.17 | BSD-3-Clause | [redis/redis, 7.2.17](https://github.com/redis/redis/blob/7.2.17/COPYING) | Разрешено |
| `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` | uv 0.9.30, Python 3.12.12, Debian 12 bookworm-slim | Apache-2.0 (uv), PSF-2.0 (Python), DFSG-свободные лицензии Debian | [astral-sh/uv](https://github.com/astral-sh/uv), [python:3.12-slim-bookworm](https://github.com/docker-library/python), [debian](https://www.debian.org/legal/licenses/) | Разрешено |

Digest на 25.11.2026 (мультиархивный индекс / linux/amd64):

| Образ | Digest индекса | Digest linux/amd64 |
| --- | --- | --- |
| `postgres:16-alpine` | `sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d` | `sha256:9d9e487c1bd6413c52ccb3c02f46c8e37fa1e1d1a32a84519eb4e68d0ad1da30` |
| `redis:7.2-alpine` | `sha256:2f66de68111e64c3927859f158f8e666066dae2b97d9f82770a6f37a5aa1c335` | `sha256:a2c8f9d7c49c74ebd2945e3798c71606545c5f0d90d03e9ec4a2bb8d4f56df36` |
| `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` | `sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58` | `sha256:5d275ca5f0da33c3368ac8fbb85fafabad023b3b8a7cff39a94ac0baecfd9a50` |

Пакеты Debian (`bookworm-slim`) и Alpine (`*-alpine`: musl, BusyBox и другие)
внутри базовых образов построчно не перечисляются: состав задаётся базовым
образом и меняется с его обновлением. Все они допускают коммерческое
использование; обязательства GPL/LGPL ограничены самими пакетами и не
распространяются на код проекта, пакеты не модифицируются.

### Почему Redis 7.2, а не 7-alpine

Тег `redis:7-alpine` 25.11.2026 указывал на Redis 7.4.12. Начиная с 7.4 Redis
распространяется по выбору между RSALv2 и SSPLv1. Это не лицензии OSI, и они
ограничивают предоставление Redis как сервиса. Поэтому в `docker-compose.yml`
закреплён `redis:7.2-alpine` (7.2.17, BSD-3-Clause). Возврат на 7.4+ или переход
на Valkey станет отдельным решением, а не следствием T-031.

## Проверка

```bash
uv tree --depth 1
uv pip list
docker image inspect postgres:16-alpine redis:7.2-alpine \
  ghcr.io/astral-sh/uv:python3.12-bookworm-slim \
  --format '{{.RepoTags}} {{index .RepoDigests 0}}'
uv run pytest
```

Как обновлять:

1. Версии Python-зависимостей: после `uv lock`/`uv add` сверить таблицу
   «Прямые зависимости» и сводку по лицензиям с `uv.lock`.
2. Версии сканеров: после изменения `ARG` в `Dockerfile.worker` обновить
   раздел «Сканеры» и таблицу в `docs/scanners.md`.
3. Образы: после смены тега в compose или Dockerfile обновить версию, digest и
   строку лицензии. Если новый тег меняет лицензию, сначала согласовать замену,
   а не дописывать исключение задним числом.
