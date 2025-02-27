# Run Anvil, build the contract, and deploy EigenLayer with one command using Foundry.
run:
		@echo "Starting Anvil..."
		nohup anvil > anvil.log 2>&1 &
		@echo "Clone eigenlayer contract"
		git clone https://github.com/Layr-Labs/eigenlayer-contracts.git
		@echo "Building contract..."
		@cd eigenlayer-contracts ; forge build
		@echo "Deploying contract..."
		cd eigenlayer-contracts ; forge script script/deploy/local/Deploy_From_Scratch.s.sol \
						--fork-url http://127.0.0.1:8545 \
						--broadcast \
						--skip-simulation \
						--sig "run(string memory)" "local/deploy_from_scratch.anvil.config.json" \
						--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 
		@echo "Deployment complete. To stop Anvil, run 'make kill'."

kill:
		@echo "Stopping Anvil..."
		killall anvil || true

