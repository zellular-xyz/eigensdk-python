#!/usr/bin/env python3
"""
Script to extract contract addresses from the EigenLayer deployment.
This can be used to update the .env file with the correct contract addresses.
"""

import json
import os
import sys
import glob
from pathlib import Path


def get_contract_addresses(quiet=False):
    """Get contract addresses from the deployment file."""
    # Look for the most recent run file
    broadcast_dir = Path("/app/eigenlayer-contracts/broadcast")

    if not broadcast_dir.exists():
        if not quiet:
            print(f"❌ Broadcast directory not found at {broadcast_dir}")
            print("Make sure you have started the Anvil service and deployed the contracts.")
            print("Run: make anvil-up")
        return get_default_addresses()

    # Find all run-latest.json files
    run_files = list(broadcast_dir.glob("**/run-latest.json"))

    if not run_files:
        if not quiet:
            print("❌ No deployment files found")
            print("Looking for backup default values...")
        return get_default_addresses()

    # Use the most recently modified file
    run_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    deploy_file = run_files[0]

    try:
        with open(deploy_file, "r") as f:
            deploy_data = json.load(f)

        # Extract contract creations
        contracts = {}
        for transaction in deploy_data.get("transactions", []):
            if transaction.get("transactionType") == "CREATE":
                contract_name = transaction.get("contractName")
                contract_address = transaction.get("contractAddress")
                if contract_name and contract_address:
                    contracts[contract_name] = contract_address

        # If no contracts found, try the second most recent file
        if not contracts and len(run_files) > 1:
            deploy_file = run_files[1]
            with open(deploy_file, "r") as f:
                deploy_data = json.load(f)

            for transaction in deploy_data.get("transactions", []):
                if transaction.get("transactionType") == "CREATE":
                    contract_name = transaction.get("contractName")
                    contract_address = transaction.get("contractAddress")
                    if contract_name and contract_address:
                        contracts[contract_name] = contract_address

        # Map contract names to the expected environment variables
        contract_mapping = {
            "StrategyManager": "STRATEGY_MANAGER_ADDR",
            "DelegationManager": "DELEGATION_MANAGER_ADDR",
            "AVSDirectory": "AVS_DIRECTORY_ADDR",
            "RegistryCoordinator": "REGISTRY_COORDINATOR_ADDR",
            "StakeRegistry": "STAKE_REGISTRY_ADDR",
            "ServiceManager": "SERVICE_MANAGER_ADDR",
            "BlsApkRegistry": "BLS_APK_REGISTRY_ADDR",
            "OperatorStateRetriever": "OPERATOR_STATE_RETRIEVER_ADDR",
            "AllocationManager": "ALLOCATION_MANAGER_ADDR",
            "PermissionController": "PERMISSION_CONTROL_ADDR",
            "RewardsCoordinator": "REWARDS_COORDINATOR_ADDR",
        }

        # Create .env content
        env_content = []
        for contract_name, env_var in contract_mapping.items():
            if contract_name in contracts:
                env_content.append(f"{env_var}={contracts[contract_name]}")
            elif not quiet:
                print(f"⚠️ Contract {contract_name} not found in deployment file")

        if not env_content:
            if not quiet:
                print("⚠️ No contract addresses found in deployment files")
                print("Using default values instead")
            return get_default_addresses()

        return env_content

    except Exception as e:
        if not quiet:
            print(f"❌ Error reading deployment file: {e}")
        return get_default_addresses()


def get_default_addresses():
    """Get default contract addresses if deployment files are not found."""
    # Default contract addresses for testing
    return [
        "STRATEGY_MANAGER_ADDR=0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
        "DELEGATION_MANAGER_ADDR=0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
        "AVS_DIRECTORY_ADDR=0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "REGISTRY_COORDINATOR_ADDR=0xa82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9",
        "STAKE_REGISTRY_ADDR=0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        "SERVICE_MANAGER_ADDR=0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        "BLS_APK_REGISTRY_ADDR=0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        "OPERATOR_STATE_RETRIEVER_ADDR=0x95401dc811bb5740090279Ba06cfA8fcF6113778",
        "ALLOCATION_MANAGER_ADDR=0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6",
        "PERMISSION_CONTROL_ADDR=0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "REWARDS_COORDINATOR_ADDR=0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        "STRATEGY_ADDR=0x09635F643e140090A9A8Dcd712eD6285858ceBef",
    ]


def main():
    """Main function."""
    print("📋 Getting contract addresses from deployment...")
    env_lines = get_contract_addresses()

    if env_lines:
        print("\n✅ Found the following contract addresses:")
        for line in env_lines:
            print(f"  {line}")

        print("\nYou can add these to your .env file to configure your tests.")
        print("To create or update your .env file automatically, run:")
        print("python scripts/get_contract_addresses.py > .env.contracts")
    else:
        print("❌ No contract addresses found")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--output-only":
        # Output only the env lines without any other text
        env_lines = get_contract_addresses(quiet=True)
        for line in env_lines:
            print(line)
    else:
        main()
