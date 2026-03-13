.PHONY: dev test test-analyzer test-backend lint build clean migrate

dev:
	docker compose up --build

test: test-analyzer test-backend

test-analyzer:
	cd analyzer && pip install -e ".[dev]" --quiet && pytest -v

test-backend:
	cd backend && pip install -r requirements.txt --quiet && pip install -e ../analyzer --quiet && pytest -v

lint:
	cd analyzer && ruff check src/ tests/
	cd backend && ruff check app/ tests/
	cd frontend && npx tsc --noEmit

build:
	cd frontend && npm ci && npm run build

clean:
	docker compose down -v --remove-orphans

migrate:
	cd backend && alembic upgrade head
