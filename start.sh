#!/bin/bash

# Start Anvil in the background
anvil &

# Wait for Anvil to be ready
sleep 5

# Deploy contracts
cd incredible-squaring-avs/contracts
export RPC_URL=http://127.0.0.1:8545
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

forge script script/DeployEigenLayerCore.s.sol:DeployEigenLayerCore --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY
forge script script/IncredibleSquaringDeployer.s.sol --rpc-url $RPC_URL --broadcast --slow --private-key $PRIVATE_KEY
forge script script/UAMPermissions.s.sol --rpc-url $RPC_URL --broadcast --slow --private-key $PRIVATE_KEY
forge script script/CreateQuorum.s.sol --rpc-url $RPC_URL --broadcast --slow --private-key $PRIVATE_KEY

# Keep the container running
wait 