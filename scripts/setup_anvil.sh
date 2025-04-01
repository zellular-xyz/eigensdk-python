#!/bin/bash

# This script sets up Anvil and deploys contracts using the Makefile

# Exit on error
set -e

echo "Starting Anvil..."
# Use make anvil-up which includes proper waiting and checks
make anvil-up

echo "Waiting for Anvil to be ready..."
# Wait for Anvil to be healthy
while ! docker compose ps anvil | grep -q "healthy"; do
    sleep 1
done
echo "Anvil is ready!"

echo "Deploying contracts..."
# Deploy contracts inside the anvil container
echo "Running deployment script..."
docker compose exec -T anvil bash -c "cd /app/eigenlayer-contracts && \
forge script script/deploy/local/deploy_from_scratch.slashing.s.sol:DeployFromScratch \
--fork-url http://127.0.0.1:8545 \
--broadcast \
--skip-simulation \
--sig 'run(string memory)' \
\"local/deploy_from_scratch.slashing.anvil.config.json\" \
--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

echo "Verifying contract deployment..."
# Check if contracts are deployed by looking for the .env file
if [ ! -f "tests/.env" ]; then
    echo "Error: Contract deployment failed - tests/.env file not found"
    exit 1
fi
echo "Contract deployment verified!"

echo "Updating environment variables..."
# Update environment variables using make
make update-env

echo "Anvil setup complete! You can now run tests against this instance."