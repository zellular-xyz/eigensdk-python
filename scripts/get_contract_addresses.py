#!/usr/bin/env python3
"""
Script to extract contract addresses from the EigenLayer deployment.
This can be used to update the .env file with the correct contract addresses.
"""
import json
import sys
from pathlib import Path

def error(message):
    print(message, file=sys.stderr)

def get_contract_addresses():
    broadcast_dir = Path("/app/eigenlayer-contracts/broadcast")

    if not broadcast_dir.exists():
        error(f"❌ Broadcast directory not found at {broadcast_dir}")
        error("Make sure you have started the Anvil service and deployed the contracts.")
        error("Run: make anvil-up")
        return get_default_addresses()

    # Find all run-latest.json files
    run_files = list(broadcast_dir.glob("**/run-latest.json"))

    assert run_files

    # Use the most recently modified file
    run_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    deploy_file = run_files[0]

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
    #if not contracts and len(run_files) > 1:
    #    deploy_file = run_files[1]
    #    with open(deploy_file, "r") as f:
    #        deploy_data = json.load(f)

    #    for transaction in deploy_data.get("transactions", []):
    #        if transaction.get("transactionType") == "CREATE":
    #            contract_name = transaction.get("contractName")
    #            contract_address = transaction.get("contractAddress")
    #            if contract_name and contract_address:
    #                contracts[contract_name] = contract_address

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

    return [f"{env_var}={contracts[contract_name]}" for contract_name, env_var in contract_mapping.items()]


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


if __name__ == "__main__":
    env_lines = get_contract_addresses()
    for line in env_lines:
        print(line)
