.PHONY: $(MAKECMDGOALS)

DOCKER_DEV = docker compose run dev

build:
	COMPOSE_BAKE=true docker compose build

rebuild:
	COMPOSE_BAKE=true docker compose build --no-cache

anvil-reset: down
	docker compose up anvil

shell:
	docker compose run test bash

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

down:
	docker compose down -v -t0 --remove-orphans

anvil-logs:
	docker compose logs anvil

test:
	docker compose run --rm test sh -c "\
		python -m pytest tests/chainio/anvil/eigenlayer/reader/test_el_reader.py && \
		python -m pytest tests/chainio/anvil/eigenlayer/writer/test_el_writer.py && \
		python -m pytest tests/chainio/anvil/avsregistry/reader/test_avs_reader.py && \
		python -m pytest tests/chainio/anvil/avsregistry/writer/test_avs_writer.py"

format:
	$(DOCKER_DEV) black .

mypy:
	$(DOCKER_DEV) mypy --ignore-missing-imports --implicit-optional eigensdk/chainio/ tests/chainio/

lint:
	$(DOCKER_DEV) flake8 eigensdk/chainio/ tests/chainio/

precommit: format mypy lint
commit-all-no-verify:
	git commit -a -n
commit-all: precommit commit-all-no-verify
