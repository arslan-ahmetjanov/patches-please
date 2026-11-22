# Задачи: Security Gate — V1

Легенда: `[P]` — можно делать параллельно. Порядок строк — порядок выполнения,
кроме T-034…T-037: они добавлены позже и идут первыми (см. «Порядок и сроки»).

Delta-спеки: [delta-001-auth.md](delta-001-auth.md) — FR-022, FR-023 (T-004);
[delta-002-tokens.md](delta-002-tokens.md) — FR-024, FR-025 (T-006);
[delta-003-status.md](delta-003-status.md) — FR-026 (T-009);
[delta-004-resilience.md](delta-004-resilience.md) — FR-027 (T-010);
[delta-005-scanner-runner.md](delta-005-scanner-runner.md) — FR-028 (T-011);
[delta-006-findings.md](delta-006-findings.md) — FR-029 (T-012);
[delta-007-scanners.md](delta-007-scanners.md) — FR-030 (T-013);
[delta-008-cli.md](delta-008-cli.md) — FR-031…FR-037, NFR-007 (T-036).

Пустой ID требования допускается только у T-034, T-035 и T-037: они меняют
имена, упаковку и оформление, а поведение системы не меняется.

| ID | Требование | Файлы | Что сделать | Проверка | Готово когда |
| --- | --- | --- | --- | --- | --- |
| T-001 | CON-002, CON-005 | `docker-compose.yml`, `Dockerfile`, `app/main.py`, `app/worker/main.py`, `Makefile`, `.env.example`, `pyproject.toml`, `contracts/openapi.yaml` | Compose с postgres, redis, api, worker; healthcheck; каркас `pyproject.toml` с pytest, ruff, mypy; `.env.example` без секретов | `docker compose up -d`, `curl /health` | стек поднимается, `/health` отдаёт 200, worker виден в `docker compose ps` |
| T-002 | NFR-005 | `app/db.py`, `alembic.ini`, `migrations/`, `README.md` | Подключение к PostgreSQL, Alembic, первая миграция `users` и `sessions` | `uv run alembic upgrade head`, перезапуск стека | миграция применяется, после рестарта данные на месте |
| T-003 | NFR-001 | `tests/conftest.py`, `.github/workflows/ci.yml` | Общие фикстуры pytest, CI на push и PR | `uv run pytest`, `uv run ruff check .` | CI зелёный на каркасе T-001 |
| T-004 | FR-022, FR-023 | `app/auth/router.py`, `app/auth/service.py`, `templates/login.html`, `tests/test_auth.py` | Вход и выход, cookie-сессия, хеш пароля | `uv run pytest tests/test_auth.py` | вход даёт сессию, неверный пароль — 401 |
| T-005 | FR-017 | `app/projects/router.py`, `app/projects/models.py`, `templates/projects.html`, `tests/test_projects.py` | Модель проекта, список и создание, изоляция по членству | `uv run pytest tests/test_projects.py` | пользователь проекта А не видит проект Б |
| T-006 | FR-024, FR-025 | `app/tokens/router.py`, `app/tokens/service.py`, `tests/test_tokens.py` | Токен проекта: создание, показ один раз, хеш в БД, отзыв | `uv run pytest tests/test_tokens.py` | повторно токен не отдаётся, отозванный не проходит |
| T-007 | FR-009 | `contracts/openapi.yaml`, `app/api.py`, `scripts/export_openapi.py`, `tests/test_contract.py` | Экспорт OpenAPI, схемы запросов и ответов, коды ошибок, схемы безопасности | `uv run pytest tests/test_contract.py` | контракт совпадает с реализацией |
| T-008 | FR-001, FR-007, FR-019 | `app/scans/router.py`, `app/scans/models.py`, `app/scans/queue.py`, `tests/test_scans.py` | `POST /scans` с токеном и `provider`, запись прогона, очередь, поллинг статуса | `uv run pytest tests/test_scans.py` | два провайдера создают прогоны одинаковой структуры |
| T-009 | FR-026 | `app/scans/service.py`, `app/scans/queue.py`, `tests/test_status.py` | Машина состояний прогона: `queued → running → done/error`, время начала и завершения, причина ошибки; воркер переводит `queued → running` | `uv run pytest tests/test_status.py` | недопустимые переходы отклоняются, `started_at`/`finished_at` заполняются один раз |
| T-010 | FR-027 | `app/worker/main.py`, `app/scans/queue.py`, `tests/test_worker_resilience.py` | Обработка падения и таймаута задачи, рестарт worker без потери истории | `uv run pytest -m integration` | после рестарта прогон либо `done`, либо `error`, но не висит |
| T-011 | FR-028 | `app/scanners/base.py`, `app/scanners/runner.py`, `tests/test_runner.py` | Общий интерфейс адаптера, параллельный запуск, общий таймаут | `uv run pytest tests/test_runner.py` | при падении одного сканера остальные завершаются |
| T-012 | FR-003, FR-029 | `app/normalize/model.py`, `app/normalize/sarif.py`, `app/normalize/fingerprint.py`, `tests/fixtures/*.sarif`, `tests/test_normalize.py` | Нормализация SARIF, fingerprint, дедупликация внутри прогона | `uv run pytest tests/test_normalize.py` | все обязательные поля заполнены, дубли схлопнуты |
| T-013 | FR-002, FR-030, NFR-003 | `Dockerfile.worker`, `docker-compose.yml`, `app/scanners/semgrep.py`, `gitleaks.py`, `trivy.py`, `process.py`, `offline.py`, `scanner-rules/semgrep/`, `tests/fixtures/scanner-repo/`, `tests/test_adapters.py`, `tests/test_process.py`, `tests/test_offline.py`, `docs/scanners.md` | Бинарники и правила в образ, офлайн-прогон | прогон с отключённой сетью на тестовом репозитории | три сканера дают SARIF без доступа в интернет |
| T-014 | FR-006, FR-016 | `app/policy/baseline.py`, `app/policy/classify.py`, `tests/test_baseline.py` | Установка baseline, сравнение, метки `new`/`existing`/`fixed` | `uv run pytest tests/test_baseline.py` | сценарий S-003 проходит на данных |
| T-015 | FR-011, FR-012 | `app/policy/exceptions.py`, `templates/exceptions.html`, `tests/test_exceptions.py` | Исключения с причиной и сроком, автоповтор после истечения, аудит | `uv run pytest tests/test_exceptions.py` | S-005 проходит, истёкшее исключение снова влияет на вердикт |
| T-016 | FR-015 | `app/metrics/service.py`, `tests/test_metrics.py` | Расчёт метрик прогона: длительность, находки, новые/исправленные, доля исключённых | `uv run pytest tests/test_metrics.py` | все пять метрик считаются и сохраняются |
| T-017 | FR-004, FR-014 | `app/policy/verdict.py`, `app/policy/router.py`, `tests/test_policy.py` | Пороги по severity и вердикт `pass`/`fail` для проекта | `uv run pytest tests/test_policy.py` | два проекта с разными порогами дают разные вердикты |
| T-018 | FR-005 | `app/policy/verdict.py`, `tests/test_blocking.py` | Блокировка при новой находке блокирующего уровня | `uv run pytest tests/test_blocking.py` | новая `critical` при политике `critical` даёт `fail` |
| T-019 | FR-013 | `app/policy/degraded.py`, `tests/test_degraded.py` | Пометка `degraded`, режимы fail-open и fail-closed | `uv run pytest tests/test_degraded.py` | упавший сканер не блокирует при fail-open и блокирует при fail-closed |
| T-020 | FR-008, FR-015 | `app/reports/json_report.py`, `app/reports/html_report.py`, `templates/report.html`, `tests/test_reports.py` | Отчёты JSON и HTML по прогону, артефакты | `uv run pytest tests/test_reports.py` | JSON валиден по схеме, HTML содержит все находки |
| T-021 | NFR-004 | `app/normalize/mask.py`, `tests/test_masking.py` | Маскирование секретов в находках, логах и отчётах | `uv run pytest tests/test_masking.py` | тестовый секрет не встречается в открытом виде ни в одном выходе |
| T-022 | FR-010, CON-004 | `templates/project.html`, `app/web/router.py`, `tests/test_web_project.py` | Страница проекта: последние прогоны, тренд, топ-5 правил, русские подписи | `uv run pytest tests/test_web_project.py` | S-006 проходит, пустых состояний при наличии данных нет |
| T-023 | FR-003, FR-018 | `templates/scan.html`, `tests/test_web_scan.py` | Страница прогона: находки с фильтрами по severity и состоянию, проверка прав | `uv run pytest tests/test_web_scan.py` | чужой проект отдаёт 403, фильтры работают |
| T-024 | FR-014, FR-011 | `templates/settings.html`, `templates/policy_form.html`, `tests/test_web_settings.py` | Формы политики и исключений с валидацией полей, CSRF-токены и secure-cookie для HTTPS | `uv run pytest tests/test_web_settings.py` | форма без причины не сохраняется |
| T-025 | FR-018 | `app/auth/permissions.py`, `tests/test_permissions.py` | Единая проверка прав на проект для API и страниц | `uv run pytest tests/test_permissions.py` | все точки доступа покрыты, 403 без утечки данных |
| T-026 | FR-019, FR-020, FR-021, FR-033 | `.github/actions/patches-please/action.yml`, `.github/workflows/demo-scan.yml`, `docs/ci-github.md` | Композитный action: установка CLI и один вызов `patches-please scan --wait`; проброс кода выхода; демо-воркфлоу | реальный прогон в GitHub | job падает при `fail` и проходит при `pass`; поллинга в самом action нет |
| T-027 | FR-019, FR-020, FR-021, FR-033 | `ci/gitlab/patches-please.yml`, `.gitlab-ci.yml`, `docs/ci-gitlab.md` | Шаблон job для GitLab на том же клиенте, инструкция, локальная проверка | `gitlab-ci-local` | пайплайн валиден и проходит локально; шаблон не дублирует поллинг |
| T-028 | FR-019 | `tests/test_parity.py` | Один коммит через два провайдера даёт одинаковый вердикт и набор проверок | `uv run pytest tests/test_parity.py` | вердикты и число находок совпадают |
| T-029 | NFR-001 | `tests/load/k6.js`, `docs/measurements.md` | Нагрузочный замер API, фиксация p95 | `k6 run tests/load/k6.js` | p95 ≤ 300 мс при 20 RPS, результат записан |
| T-030 | NFR-002 | `scripts/measure_scan.py`, `docs/measurements.md` | Замер прогона на репозитории до 100 тыс. строк, три повтора | `uv run python scripts/measure_scan.py` | максимум ≤ 10 минут, цифры записаны |
| T-031 | CON-001 | `docs/licenses.md`, `README.md` | Список лицензий сканеров и зависимостей, проверка разрешительности | ревью таблицы лицензий | все лицензии разрешительные, таблица в репозитории |
| T-032 | CON-003 | `demo/README.md`, `scripts/seed_demo.py`, `docs/demo.md` | Демо-репозиторий с внедрёнными уязвимостями и секретами, без данных работодателя | прогон на демо | находятся все три класса находок, запрещённых данных нет |
| T-033 | NFR-006, CON-004 | `docs/runbook.md`, `README.md` | Инструкция развёртывания с нуля на русском, хронометраж; предусловия: установка `uv` и запуск Docker Desktop | чистая машина, замер по инструкции | развёртывание ≤ 30 минут |
| T-034 | — | `pyproject.toml`, `uv.lock`, `docker-compose.yml`, `.env.example`, `app/` → `patches_please/`, `contracts/openapi.yaml`, `scripts/export_openapi.py`, `templates/`, `tests/`, `README.md`, `AGENTS.md`, `docs/`, `specs/` | Переименование продукта в «Patches, Please»: бренд в текстах, `app/` → `patches_please/`, cookie `pp_session`, префикс токена `pp_`, БД `patches_please*`, очередь и образы `patches-please` | `uv run pytest`, `uv run mypy patches_please`, `uv run ruff check .`, `uv run python scripts/export_openapi.py`, `docker compose up -d` с пустого volume | в коде и документации нет `security-gate`/`security_gate`, кроме цитаты названия запроса в `docs/source-request.md` и истории git; стек поднимается с нуля |
| T-035 | — | `pyproject.toml`, `scripts/check_wheel.py` | `[build-system]` на hatchling, `packages = ["patches_please"]`, шаблоны и миграции внутри wheel, `uv build` | `uv build`, установка wheel в чистый venv, `python -c "import patches_please"` | wheel собирается и ставится без исходников, модуль импортируется из установленного пакета; точка входа появляется в T-036 |
| T-036 | FR-031…FR-037, NFR-007 | `patches_please/cli.py`, `pyproject.toml` (`[project.scripts]`, `httpx` в зависимостях), `tests/test_cli.py`, `docs/ci-github.md` | Клиент: аргументы, старт прогона, ожидание с таймаутом, таблица кодов выхода, `--json`, повторы на `5xx`, маскирование токена | `uv run pytest tests/test_cli.py` | код 0 при `pass`, 1 при `fail`, коды 2–6 различимы, токен не попадает ни в stdout, ни в stderr |
| T-037 | CON-004 | `docs/brand.md`, `templates/static/brand.css`, `templates/*.html`, `tests/test_web_scan.py` | Применить паспорт стиля: словарь «досмотр/пропущен/задержан», штамп вердикта, палитра, два шрифта с кириллицей | просмотр страниц, `uv run pytest tests/test_web_*.py` | на странице прогона и в отчёте штамп, подписи по словарю, пиксельный шрифт не попадает в тело текста |

## Трассировка

| Требование | Задачи | Тесты |
| --- | --- | --- |
| FR-001 | T-008 | `tests/test_scans.py` |
| FR-002 | T-013 | `tests/test_adapters.py`, офлайн-прогон трёх сканеров |
| FR-003 | T-012, T-023 | `tests/test_normalize.py`, `tests/test_web_scan.py` |
| FR-004 | T-017 | `tests/test_policy.py` |
| FR-005 | T-018 | `tests/test_blocking.py` |
| FR-006 | T-014 | `tests/test_baseline.py` |
| FR-007 | T-008 | `tests/test_scans.py` |
| FR-008 | T-020 | `tests/test_reports.py` |
| FR-009 | T-007, T-008 | `tests/test_contract.py`, `tests/test_scans.py` |
| FR-010 | T-022 | `tests/test_web_project.py` |
| FR-011 | T-015, T-024 | `tests/test_exceptions.py`, `tests/test_web_settings.py` |
| FR-012 | T-015 | `tests/test_exceptions.py` |
| FR-013 | T-019 | `tests/test_degraded.py` |
| FR-014 | T-017, T-024 | `tests/test_policy.py`, `tests/test_web_settings.py` |
| FR-015 | T-016, T-020 | `tests/test_metrics.py`, `tests/test_reports.py` |
| FR-016 | T-014 | `tests/test_baseline.py` |
| FR-017 | T-005 | `tests/test_projects.py` |
| FR-018 | T-023, T-025 | `tests/test_permissions.py`, `tests/test_web_scan.py` |
| FR-019 | T-008, T-026, T-027, T-028, T-036 | `tests/test_scans.py`, `tests/test_cli.py`, `tests/test_parity.py`, демо-пайплайны |
| FR-020 | T-026, T-027, T-036 | `tests/test_cli.py` (`test_fr_033_*`), GitHub demo-воркфлоу, `gitlab-ci-local` |
| FR-021 | T-026, T-027 | `docs/ci-github.md`, `docs/ci-gitlab.md` |
| FR-022 | T-004 | `tests/test_auth.py` (`test_fr_022_*`) |
| FR-023 | T-004 | `tests/test_auth.py` (`test_fr_023_*`) |
| FR-024 | T-006 | `tests/test_tokens.py` (`test_fr_024_*`) |
| FR-025 | T-006 | `tests/test_tokens.py` (`test_fr_025_*`) |
| FR-026 | T-009 | `tests/test_status.py` (`test_fr_026_*`) |
| FR-027 | T-010 | `tests/test_worker_resilience.py` (`test_fr_027_*`) |
| FR-028 | T-011 | `tests/test_runner.py` (`test_fr_028_*`) |
| FR-029 | T-012 | `tests/test_normalize.py` (`test_fr_029_*`) |
| FR-030 | T-013 | `tests/test_process.py`, `tests/test_adapters.py`, `tests/test_offline.py` (`test_fr_030_*`) |
| FR-031 | T-036 | `tests/test_cli.py` (`test_fr_031_*`) |
| FR-032 | T-036 | `tests/test_cli.py` (`test_fr_032_*`) |
| FR-033 | T-036, T-026, T-027 | `tests/test_cli.py` (`test_fr_033_*`), прогон в GitHub |
| FR-034 | T-036 | `tests/test_cli.py` (`test_fr_034_*`) |
| FR-035 | T-036 | `tests/test_cli.py` (`test_fr_035_*`) |
| FR-036 | T-036 | `tests/test_cli.py` (`test_fr_036_*`) |
| FR-037 | T-036, T-028 | `tests/test_cli.py` (`test_fr_037_*`), `tests/test_parity.py` |
| NFR-001 | T-003, T-029 | `tests/load/k6.js`, `docs/measurements.md` |
| NFR-002 | T-030 | `scripts/measure_scan.py` |
| NFR-003 | T-013 | офлайн-прогон на тестовом репозитории, `docs/scanners.md` |
| NFR-004 | T-021 | `tests/test_masking.py` |
| NFR-005 | T-002 | перезапуск стека, история на месте |
| NFR-006 | T-033 | `docs/runbook.md` |
| NFR-007 | T-036 | `tests/test_cli.py` (`test_nfr_007_*`) |
| CON-001 | T-031 | `docs/licenses.md` |
| CON-002 | T-001 | `docker compose up` |
| CON-003 | T-032 | прогон на демо, ревью данных |
| CON-004 | T-022, T-033 | страницы и документация на русском |
| CON-005 | T-001 | запуск на целевой машине |

## Порядок и сроки

| Этап | Задачи | Оценка |
| --- | --- | --- |
| 0. Ребрендинг и упаковка | T-034, T-035 | 1 день |
| 1. Скелет | T-001…T-003 | 3 дня |
| 2. Проекты и доступ | T-004…T-007 | 4 дня |
| 3. Прогон и очередь | T-008…T-010 | 4 дня |
| 4. Сканеры и нормализация | T-011…T-013 | 1 неделя |
| 5. Baseline и исключения | T-014, T-015 | 3 дня |
| 6. Метрики, политика, вердикт | T-016…T-019 | 4 дня |
| 7. Отчёты | T-020, T-021 | 3 дня |
| 8. Интерфейс | T-022…T-025, T-037 | 6 дней |
| 9. Клиент и CI-интеграции | T-036, T-026…T-028 | 6 дней |
| 10. Замеры и документация | T-029…T-033 | 4 дня |

Итого около 8,5 недель работы плюс две недели буфера на текст ВКР и правки.
Защита в феврале — запас есть.

T-034 идёт после T-013: переименование каталога `app/` задевает файлы, которые
создаёт задача по сканерам. Пока они не закоммичены, переименование делается
один раз и без конфликтов слияния.
