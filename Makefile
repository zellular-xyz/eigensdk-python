.PHONY: $(MAKECMDGOALS)

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
		python -m pytest -s tests/chainio/test_avs_writer.py && \
		python -m pytest -s tests/chainio/test_el_reader.py && \
		python -m pytest -s tests/chainio/test_el_writer.py && \
		python -m pytest -s tests/chainio/test_avs_reader.py"

fresh-test: down
	docker compose up -d anvil
	sleep 3
	$(MAKE) test

format:
	$(DOCKER_DEV) black .

format-check:
	black --check .

mypy:
	mypy --ignore-missing-imports --implicit-optional .

lint:
	flake8 .

precommit: format-check mypy lint
commit-all-no-verify:
	git commit -a -n
commit-all: precommit commit-all-no-verify
