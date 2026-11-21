.PHONY: up down restart ps logs build test lint fmt type check

# Стек Docker Compose
up:
	docker compose up -d --build

down:
	docker compose down

restart: down up

ps:
	docker compose ps

logs:
	docker compose logs -f --tail=100

build:
	docker compose build

# Качество кода
test:
	uv run pytest -m "not integration"

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

type:
	uv run mypy app

check: lint type test
