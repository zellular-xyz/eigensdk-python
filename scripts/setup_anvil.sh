#!/bin/bash

# Exit on error
set -e

echo "Starting Anvil..."
# Start Anvil in the background
docker compose up -d anvil

echo "Waiting for Anvil to be ready..."
# Wait for Anvil to be healthy using docker compose
while ! docker compose ps anvil | grep -q "healthy"; do
    sleep 1
done
echo "Anvil is ready!"

echo "Deploying contracts..."
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
# Update environment variables
docker compose run --rm app python scripts/update_env.py

echo "Anvil setup complete! You can now run tests against this instance."