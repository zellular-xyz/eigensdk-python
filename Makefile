.PHONY: $(MAKECMDGOALS)

# Build the Docker image
build:
	docker compose build

# Run basic tests (without Anvil dependency)
basic-test:
	docker compose run --no-deps app python3 -m pytest tests/public/test_imports.py tests//public/test_no_chain.py

# Format code with black
format:
	docker compose run app black .

# Open a shell in the container
shell:
	docker compose run app bash

# Clean up containers and build artifacts
clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

down:
	docker compose down -v -t0 --remove-orphans

# Check Anvil container logs
anvil-logs:
	docker compose logs anvil


# Start anvil in the background and deploy contracts
anvil-up:
	make check-ports
	docker compose up -d anvil
	@echo "Waiting for Anvil to start up and deploy contracts..."
	@sleep 10
	@docker logs --tail 20 eigensdk-python-anvil-1

# Anvil shell for working with foundry
anvil-shell:
	docker compose run anvil bash

# Get the contract addresses from the deployment
get-addresses:
	docker compose run app python3 scripts/get_contract_addresses.py

# Update the .env file with contract addresses
update-env:
	docker compose run app python3 scripts/update_env.py

# Full setup: build, start anvil, update env, run tests
setup-all: build down anvil-up update-env deploy-and-test

# Simple setup for running tests without blockchain dependency
simple-setup: build down update-env basic-test 


deploy-and-test: down
	./scripts/deploy_and_test.sh 

mypy:
	docker compose run app mypy eigensdk

lint:
	docker compose run app flake8 .
