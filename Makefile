.PHONY: $(MAKECMDGOALS)

DOCKER_DEV = docker compose run dev

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
	docker compose run --rm test sh -c "\
		python -m pytest tests/chainio/anvil/eigenlayer/reader/test_el_reader.py && \
		python -m pytest tests/chainio/anvil/eigenlayer/writer/test_el_writer.py && \
		python -m pytest tests/chainio/anvil/avsregistry/reader/test_avs_reader.py && \
		python -m pytest tests/chainio/anvil/avsregistry/writer/test_avs_writer.py"

# Format code with black
format:
	$(DOCKER_DEV) black .

mypy:
	$(DOCKER_DEV) mypy --ignore-missing-imports eigensdk/chainio/

lint:
	$(DOCKER_DEV) flake8 eigensdk/chainio/

precommit: format mypy lint
commit-all-no-verify:
	git commit -a -n
commit-all: precommit commit-all-no-verify

