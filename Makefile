.PHONY: $(MAKECMDGOALS)

build:
	COMPOSE_BAKE=true docker compose build

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

# Get the contract addresses from the deployment
get-addresses:
	docker compose run test python3 scripts/get_contract_addresses.py

# Update the .env file with contract addresses
update-env:
	docker compose run test scripts/update_env.py

# Run tests against the running Anvil instance
test: update-env
	docker compose run --rm test python -m pytest tests/ -v

# ********** dev targets **********

# Format code with black
format:
	docker compose run dev black .

mypy:
	docker compose run dev mypy eigensdk

lint:
	docker compose run dev flake8 .
