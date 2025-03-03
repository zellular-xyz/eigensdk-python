run:
	@echo "Starting Anvil..."
	nohup anvil > anvil.log 2>&1 &
	@echo "Clone eigenlayer contract"
	@if [ ! -d "eigenlayer-contracts" ]; then git clone https://github.com/Layr-Labs/eigenlayer-contracts.git; fi
	@echo "Building contract..."
	@cd eigenlayer-contracts && forge build
	@echo "Deploying contract..."
	cd eigenlayer-contracts && forge script script/deploy/local/Deploy_From_Scratch.s.sol \
					--fork-url http://127.0.0.1:8545 \
					--broadcast \
					--skip-simulation \
					--sig "run(string memory)" "local/deploy_from_scratch.anvil.config.json" \
					--private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 
	@echo "Deployment complete. To stop Anvil, run 'make kill'."

