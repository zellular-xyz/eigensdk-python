#!/bin/bash

# This script automates the process of starting Anvil, deploying contracts, and running tests

# Exit on error
set -e

echo "Starting Anvil..."
# Start Anvil in the background
docker compose up -d anvil

echo "Running deployment script..."
# Run the deployment script inside the anvil container
docker compose exec -T anvil bash -c "cd /app/eigenlayer-contracts && \
forge script script/deploy/local/deploy_from_scratch.slashing.s.sol:DeployFromScratch \
--fork-url http://127.0.0.1:8545 \
--broadcast \
--skip-simulation \
--sig 'run(string memory)' \
\"local/deploy_from_scratch.slashing.anvil.config.json\" \
--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "Updating environment variables..."
# Update the environment with contract addresses
docker compose run --rm app python scripts/update_env.py

echo "Running tests..."
# Run tests
docker compose run --rm app bash -c "cd /app && python -m pytest tests/ -v"

echo "All done!" 
