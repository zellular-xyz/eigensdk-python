#!/usr/bin/env python3
"""
Script to deploy EigenLayer contracts to Anvil for testing.

This requires the EigenLayer contracts to be cloned and compiled.

Usage:
    python deploy_contracts.py
"""

import json
import os
import subprocess

from eth_account import Account
from web3 import Web3

# Connect to Anvil
ANVIL_URL = "http://localhost:8545"
web3 = Web3(Web3.HTTPProvider(ANVIL_URL))

# Check if Anvil is running
if not web3.is_connected():
    print("Anvil is not running. Please start Anvil with 'anvil' command first.")
    exit(1)

# Default Anvil account with private key
ANVIL_PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ACCOUNT = Account.from_key(ANVIL_PRIVATE_KEY)
print(f"Using deployer account: {DEPLOYER_ACCOUNT.address}")

# Check balance
balance = web3.eth.get_balance(DEPLOYER_ACCOUNT.address)
print(f"Deployer balance: {web3.from_wei(balance, 'ether')} ETH")

# Path to EigenLayer contracts repo (adjust as needed)
EIGENLAYER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../../eigenlayer-contracts")
)

# Check if the directory exists
if not os.path.exists(EIGENLAYER_DIR):
    print(f"EigenLayer contracts directory not found at {EIGENLAYER_DIR}")
    print("Please clone the EigenLayer contracts repo or adjust the path in the script.")
    exit(1)

print(f"Using EigenLayer contracts at: {EIGENLAYER_DIR}")


# Function to run deployment command
def run_deployment_command(command):
    try:
        # Run the command in the EigenLayer contracts directory
        result = subprocess.run(
            command, shell=True, cwd=EIGENLAYER_DIR, capture_output=True, text=True, check=True
        )
        print(f"Command executed successfully: {command}")
        print(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error output: {e.stderr}")
        raise e


# Make sure the EigenLayer contracts are compiled
print("Compiling EigenLayer contracts...")
try:
    run_deployment_command("forge build")
except Exception as e:
    print(
        "Failed to compile contracts. Make sure Foundry is installed and the contracts can be compiled."
    )
    exit(1)

# Deploy the EigenLayer contracts to Anvil
print("\nDeploying EigenLayer contracts to Anvil...")

try:
    # Script to deploy core contracts (adjust based on EigenLayer repo structure)
    deploy_script = "script/anvil/DeployForTest.s.sol:DeployForTest"

    # Run the deployment script
    output = run_deployment_command(
        f"forge script {deploy_script} --rpc-url {ANVIL_URL} "
        f"--private-key {ANVIL_PRIVATE_KEY} --broadcast"
    )

    print("\nDeployment completed successfully!")

    # Parse the deployment output to extract contract addresses
    # This depends on the format of the deployment script output
    # You might need to adjust this or use a deployment file if the script saves addresses

    # Example parsing (adjust based on actual output)
    contract_addresses = {}
    for line in output.split("\n"):
        if "Deployed" in line and "at" in line:
            parts = line.split("Deployed")[1].split("at")
            if len(parts) >= 2:
                contract_name = parts[0].strip()
                address = parts[1].strip()
                contract_addresses[contract_name] = address

    # Save the contract addresses to a file
    addresses_file = os.path.join(os.path.dirname(__file__), "contract_addresses.json")
    with open(addresses_file, "w") as f:
        json.dump(contract_addresses, f, indent=2)

    print(f"\nContract addresses saved to: {addresses_file}")
    print("You can now use these addresses in your tests.")

    # Instructions for testing
    print("\nTo run tests with these deployed contracts:")
    print("1. Update the contract addresses in test_with_anvil.py")
    print("2. Run the tests with:")
    print(
        "   ANVIL_RUNNING=1 CONTRACTS_DEPLOYED=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py"
    )

except Exception as e:
    print(f"Deployment failed with error: {e}")
    print("\nTroubleshooting tips:")
    print("1. Make sure Anvil is running on port 8545")
    print("2. Make sure the EigenLayer contracts are properly set up")
    print("3. Check the forge scripts in the EigenLayer repo")

if __name__ == "__main__":
    pass
