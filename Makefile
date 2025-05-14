.PHONY: $(MAKECMDGOALS)

build:
	COMPOSE_BAKE=true docker compose build

rebuild:
	COMPOSE_BAKE=true docker compose build --no-cache

anvil-reset: down
	docker compose up anvil

# Run basic tests (without Anvil dependency)
basic-test:
	docker compose run --no-deps test python3 -m pytest tests/public/test_imports.py tests//public/test_no_chain.py

shell:
	docker compose run test bash

# Clean up containers and build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

down:
	docker compose down -v -t0 --remove-orphans

anvil-logs:
	docker compose logs anvil

# create the .env file with contract addresses
create-env:
	docker compose run test scripts/create_env.py

# Run tests against the running Anvil instance
test: 
	docker compose run --rm test python -m pytest tests/ -v

# ********** dev targets **********

# Format code with black
format:
	docker compose run dev black .

mypy:
	docker compose run dev mypy --ignore-missing-imports eigensdk/chainio/

lint:
	docker compose run dev flake8 eigensdk/chainio/

precommit: format mypy lint
commit-all-no-verify:
	git commit -a -n
commit-all: precommit commit-all-no-verify

