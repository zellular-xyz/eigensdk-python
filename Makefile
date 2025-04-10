.PHONY: $(MAKECMDGOALS)

build:
	COMPOSE_BAKE=true docker compose build

anvil-reset: down
	docker compose up anvil

# Run basic tests (without Anvil dependency)
basic-test:
	docker compose run --no-deps app python3 -m pytest tests/public/test_imports.py tests//public/test_no_chain.py

# Format code with black
format:
	docker compose run app black .

shell:
	docker compose run app bash

# Clean up containers and build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

down:
	docker compose down -v -t0 --remove-orphans

anvil-logs:
	docker compose logs anvil


# Get the contract addresses from the deployment
get-addresses:
	docker compose run app python3 scripts/get_contract_addresses.py

# Update the .env file with contract addresses
update-env:
	docker compose run app python3 scripts/update_env.py

# Full setup: build, start anvil, update env, run tests
setup-all: build  test

# Simple setup for running tests without blockchain dependency
simple-setup: build update-env basic-test 

# Run tests against the running Anvil instance
test: update-env
	docker compose run --rm app bash -c "python -m pytest tests/ -v"

mypy:
	docker compose run app mypy eigensdk

lint:
	docker compose run app flake8 .
