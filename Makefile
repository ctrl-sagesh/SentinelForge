.PHONY: install test lint format typecheck evaluate serve dashboard run seed audit docker-build docker-up docker-down clean

install:
	pip install -e ".[all]"

test:
	python -m pytest tests/ -q

test-verbose:
	python -m pytest tests/ -v

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

typecheck:
	mypy src/sentinelforge/ --ignore-missing-imports

evaluate:
	python -m sentinelforge.cli evaluate

serve:
	python -m sentinelforge.cli serve

dashboard:
	python -m sentinelforge.cli dashboard

run:
	python -m sentinelforge.cli run --scenario brute_force

run-llm:
	python -m sentinelforge.cli run --scenario brute_force --llm

seed:
	python -m sentinelforge.cli seed

audit-verify:
	python -m sentinelforge.cli audit --verify

audit-export:
	python -m sentinelforge.cli audit --export csv --since 24h

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

clean:
	rm -rf .venv __pycache__ .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
