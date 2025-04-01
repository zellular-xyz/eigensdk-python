.PHONY: $(MAKECMDGOALS)

# Build the Docker image and setup Anvil with deployed contracts
build:
	docker compose build
	@echo "Starting Anvil and deploying contracts..."
	@docker compose up -d anvil
	@echo "Waiting for Anvil to be ready..."
	@sleep 10
	@docker compose exec -T anvil bash -c "cd /app/eigenlayer-contracts && \
		forge script script/deploy/local/deploy_from_scratch.slashing.s.sol:DeployFromScratch \
		--fork-url http://127.0.0.1:8545 \
		--broadcast \
		--skip-simulation \
		--sig 'run(string memory)' \
		\"local/deploy_from_scratch.slashing.anvil.config.json\" \
		--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	@echo "Updating environment variables..."
	@docker compose run --rm app python3 scripts/update_env.py
	@echo "Anvil is ready with deployed contracts!"

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
setup-all: build  test

# Simple setup for running tests without blockchain dependency
simple-setup: build basic-test 

# Run tests against the running Anvil instance
test:
	@echo "Checking if Anvil is running..."
	@if ! docker compose ps anvil | grep -q "Up"; then \
		echo "Anvil is not running. Please run 'make anvil-up' first to start Anvil."; \
		echo "Current Anvil status:"; \
		docker compose ps anvil; \
		exit 1; \
	fi
	@echo "Checking if Anvil is responding to RPC calls..."
	@if ! docker compose exec -T anvil curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://localhost:8545 > /dev/null; then \
		echo "Anvil is not responding to RPC calls. Please check the Anvil logs with 'make anvil-logs'"; \
		exit 1; \
	fi
	@echo "Checking if contracts are deployed..."
	@if [ ! -f "tests/.env" ]; then \
		echo "Contracts appear to be not deployed. Please run 'make anvil-up' first."; \
		exit 1; \
	fi
	@echo "Running tests..."
	@docker compose run --rm app bash -c "cd /app && python -m pytest tests/ -v"

mypy:
	docker compose run app mypy eigensdk

lint:
	docker compose run app flake8 .
