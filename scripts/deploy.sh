#!/bin/bash
set -e
echo "Deploying contracts..."

(
	cd /app/eigenlayer-contracts && \
	forge script script/deploy/local/deploy_from_scratch.slashing.s.sol:DeployFromScratch \
	--rpc-url http://127.0.0.1:8545 \
	--broadcast \
	--skip-simulation \
	--sig "run(string memory)" \
	"local/deploy_from_scratch.slashing.anvil.config.json" \
	--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
)

echo "Verifying contract deployment..."

echo "Creating environment variables..."

python3 scripts/create_env.py

echo "Anvil setup complete! You can now run tests against this instance."