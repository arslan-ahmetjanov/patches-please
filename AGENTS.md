# AGENTS.md

Инструкции для агентов в репозитории Patches, Please. Общение и документация на русском.

## Проект

Автоматизированный контроль безопасности разработки для CI/CD: сканеры → единая модель находок → политика → вердикт `pass`/`fail` → блокировка пайплайна. ВКР (09.03.03, УГНТУ). Remote: `arslan-ahmetjanov/patches-please`, ветка `main`.

## Процесс: SDD

Правду задаёт спецификация, код следует за ней.

- Перед задачей прочитай `specs/patches-please-mvp/spec.md`, `plan.md`, `tasks.md` и delta-спеку этой задачи.
- Изменение поведения начинается с правки спеки или новой delta-спеки, а не с кода. Если код и спека расходятся, остановись и спроси; молча подгонять спеку под код запрещено.
- Задача без ID требования не выполняется. Исключения: T-034, T-035, T-037 (упаковка, имена, оформление).
- Строки в `tasks.md` идут в порядке выполнения, кроме оговорок в «Легенде» и «Порядок и сроки».
- Каждая задача в отдельном коммите: код, тесты, при необходимости спека. Проверка из задачи должна быть выполнена.
- Поведение после фиксации V1 меняется delta-спекой `delta-NNN-*.md`: файл попадает в список delta-спек в шапке `tasks.md`, его требования попадают в «Трассировку».

## Структура

```
patches_please/           # пакет: main.py (api), worker/, домены auth, projects, tokens,
                          # scans, policy, normalize, scanners, reports, metrics, web;
                          # templates/ и migrations/ лежат внутри пакета (T-035)
contracts/                # артефакты: openapi.yaml, report.schema.json
specs/patches-please-mvp/ # спека, план, задачи, delta-спеки
tests/                    # pytest, фикстуры SARIF и scanner-repo
scanner-rules/semgrep/    # локальные правила, запекаются в образ worker
scripts/                  # экспорт контрактов, проверка wheel, замеры, демо-сев
docs/                     # сканеры, CI, лицензии, замеры, runbook, демо, бренд
ci/gitlab/                # шаблон job для GitLab (T-027), рядом .gitlab-ci.yml
site/                     # сайт документации для GitHub Pages: статический
                          # HTML и CSS, без сборки и внешних зависимостей
demo/                     # исходник отдельного публичного демо-репозитория (T-032)
```

`demo/` не входит в образы продукта: worker клонирует опубликованную копию по
`repo_url`. `ci/` держит шаблоны интеграций, а композитное действие GitHub
лежит в `.github/actions/patches-please/`.

## Стек

Python 3.12, FastAPI, SQLAlchemy 2.0 + Alembic, PostgreSQL 16, Redis 7.2 + RQ, Jinja2, pytest, ruff, mypy strict. Всё через Docker Compose.

## Команды

```bash
uv sync                                   # зависимости; uv.lock коммитится, менять через uv add
docker compose up -d --build              # postgres, redis, api, worker
curl http://localhost:8000/health         # {"status":"ok"}
uv run alembic upgrade head               # миграции с хоста, PostgreSQL поднята
uv run alembic check                      # модели и схема БД не разошлись
uv run ruff format --check .              # формат, в CI обязателен
uv run ruff check .                       # линт
uv run mypy patches_please                # mypy strict из pyproject.toml
uv run pytest -m "not integration"        # быстрые тесты, база не нужна
uv run pytest -m integration              # нужен docker compose up -d
uv run pytest tests/test_blocking.py -k fr_005   # один тест
```

`make check` = линт + типы + быстрые тесты; формат и контракт он не проверяет, поэтому зелёный `make check` не гарантирует зелёный CI.

## CI

`.github/workflows/ci.yml`, job `quality`: `ruff format --check` → `ruff check` → `mypy` → `pytest tests/test_contract.py` → `pytest -m "not integration"`. Job `integration` поднимает `postgres:16`, применяет миграции и гоняет `-m integration`.

## Подводные камни

- `contracts/openapi.yaml` и `contracts/report.schema.json` генерируются, руками их не правят. После правки роутера или модели отчёта перегенерируй: `uv run python -m scripts.export_openapi` / `uv run python -m scripts.export_report_schema`, затем `tests/test_contract.py` / `tests/test_reports.py`.
- `tests/test_contract.py` сравнивает файл с `app.openapi()` целиком. Расхождение чинится перегенерацией, а не правкой YAML.
- HTTP-тесты идут через `httpx.ASGITransport` и не требуют запущенного сервера. Тестам с БД нужна фикстура `db_client`; сервер и учётные данные берутся из `DATABASE_URL`.
- Интеграционные фикстуры сами создают `patches_please_test`, применяют Alembic и откатывают транзакцию после каждого теста. Базу стенда они не трогают; полный URL задаётся `TEST_DATABASE_URL`.
- Комментарии в `alembic.ini` только ASCII: Alembic читает файл в кодировке системы, кириллица ломает миграции на Windows.
- Миграции лежат в `patches_please/migrations/versions/`. Имена ограничений заданы явно (`NAMING_CONVENTION` в `db.py`), поэтому автогенерацию сверяй через `alembic check`.
- Сканеры (Semgrep, Gitleaks, Trivy) живут только в образе worker: `Dockerfile.worker`, офлайн, правила и база Trivy внутри. API-образ лёгкий; сканеры не добавляются в `pyproject.toml`.
- Прогон выполняет worker через очередь RQ, API только принимает запрос и ставит задачу. Логику сканирования в API не добавляй.
- Секреты в находках маскируются на этапе нормализации, а не в шаблоне отчёта.
- Стили интерфейса и сайта совпадают: общий блок между маркерами `shared:brand` есть и в `patches_please/templates/static/brand.css`, и в `site/assets/style.css`. Правку токенов, шрифтов, штампа или кнопок переноси в оба файла, иначе падает `tests/test_brand.py`.
- Шаблоны страниц приложения запечены в образы `api` и `worker`: после правки HTML или CSS нужен `docker compose up -d --build`, иначе стенд покажет старую вёрстку.
- Раздел «Статус» в README отстаёт от кода, сверяйся с `git log` и `tasks.md`.

## Соглашения

- Интерфейс, документация и сообщения коммитов на русском; код, имена, таблицы на английском.
- Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.
- Имя теста содержит ID требования: `test_fr_005_blocks_on_new_critical`.
- UI и отчёт следуют `docs/brand.md`: отображаемое имя «Patches, Please», в идентификаторах дефис или подчёркивание (`patches-please`, `patches_please`), словарь интерфейса отличается от API (`scan`/`pass`/`fail` → «досмотр/пропущен/задержан»).

## Границы

**Всегда:** тесты перед коммитом, валидация входов на границе API, обратимая миграция, маскирование находок-секретов.

**Спросить:** изменение схемы БД после первого прогона, новая зависимость, правка CI-шаблонов, изменение формата отчёта, выход за скоуп текущей задачи.

**Никогда:** данные работодателя в репозиторий, отчёты и коммиты; секреты в открытом виде; `docker.sock` внутри worker; удаление падающего теста без разбора; правка чужих файлов «заодно».

## Готово, когда

- Проверка из задачи `tasks.md` выполнена; тесты зелёные, `ruff format --check`, `ruff check` и `mypy` чистые.
- Контракты перегенерированы, если менялись схемы.
- Спека или delta и контракт соответствуют фактическому поведению.
- В отчёте перечислено, что осталось вне скоупа.
