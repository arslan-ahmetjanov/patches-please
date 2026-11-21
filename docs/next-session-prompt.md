# Промпт для следующей сессии

Скопировать целиком в новую сессию. Рабочая директория — `C:\Users\arsla\Desktop\security-gate`.

---

```text
Продолжаем дипломный проект Security Gate.

Рабочая папка: C:\Users\arsla\Desktop\security-gate
Репозиторий: https://github.com/arslan-ahmetjanov/security-gate (private, ветка main)

Что это: информационная система автоматизированного контроля безопасности разработки
(Security Gate) для CI/CD. ВКР по 09.03.03 «Прикладная информатика», УГНТУ.
Защита — февраль 2027.

Перед работой прочитай целиком:
- AGENTS.md
- specs/security-gate-mvp/spec.md
- specs/security-gate-mvp/plan.md
- specs/security-gate-mvp/tasks.md

Состояние: спецификация V1, план и задачи готовы и закоммичены. Кода ещё нет.
Процесс — SDD: спецификация источник правды, изменение поведения начинается со спеки,
одна задача — один коммит, тест ссылается на ID требования.

Решения, которые уже приняты, не переспрашивай:
- CI: GitHub Actions основной, GitLab CI второй, оба через один REST API.
- Веб-интерфейс: простой серверный, Jinja2 + HTMX, без сборки фронтенда.
- Экономическая часть: только демо-стенд, данные работодателя не используются.
- Стек: Python 3.12, FastAPI, SQLAlchemy 2 + Alembic, PostgreSQL 16, Redis + RQ,
  uv, pytest, ruff, mypy, Docker Compose.

Задача на сессию: T-001 из tasks.md — скелет проекта.
Файлы: docker-compose.yml, Dockerfile, app/main.py, Makefile, .env.example.
Сделать: compose с postgres, redis, api и worker; healthcheck; .env.example без секретов.
Проверка: docker compose up -d, curl /health отдаёт 200, worker виден в docker compose ps.
Готово когда: стек поднимается, healthcheck отвечает, тесты и линт проходят, коммит один.

Границы:
- Никаких данных Совкомбанка, секретов в репозитории, docker.sock внутри worker.
- Не расширяй скоуп: следующие задачи берём только после T-001.
- Новую зависимость или изменение схемы БД — сначала спроси.
- Интерфейс и документация на русском, коммиты Conventional Commits на русском.

В конце отчитайся: что сделано, чем проверено (фактические команды и вывод),
что осталось вне скоупа, какие вопросы возникли.
```
