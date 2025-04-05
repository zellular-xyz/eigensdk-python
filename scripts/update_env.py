#!/usr/bin/env python3

import os
import subprocess
import sys
from pathlib import Path


def main():
    script_path = Path(__file__).parent / "get_contract_addresses.py"

    os.makedirs(os.path.dirname("tests/.env"), exist_ok=True)
    os.path.isfile("tests/.env") or open("tests/.env", "w").close()

    env_path = Path("tests/.env")

    output = subprocess.check_output(
        [sys.executable, str(script_path), "--output-only"], universal_newlines=True
    )
    contract_lines = output.strip().split("\n")

    if not contract_lines or not contract_lines[0]:
        contract_lines = [
            "IERC20_ADDR=0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
            "ISTRATEGY_ADDR=0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
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

    # Handle main .env file
    required_vars = {
        "OPERATOR_ECDSA_PRIVATE_KEY": "0x113d0ef74250eab659fd828e62a33ca72fcb22948897b2ed66b1fa695a8b9313",
        "OPERATOR_BLS_PRIVATE_KEY": "16778642697926432730636765260015002075875516459203485013999501605376283193328",
        "SENDER_ADDRESS": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "PRIVATE_KEY": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "ETH_HTTP_URL": "http://anvil:8545",
        "AVS_NAME": "test1",
        "PROM_METRICS_IP_PORT_ADDRESS": "localhost:9090",
        "IERC20_ADDR": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
        "ISTRATEGY_ADDR": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
    }

    # Read existing .env file or create a new one
    env_lines = []
    if env_path.exists():
        with open(env_path, "r") as f:
            env_lines = f.read().splitlines()

    # Filter out any contract-related variables from main .env
    contract_vars = [line.split("=")[0] for line in contract_lines]
    env_lines = [
        line
        for line in env_lines
        if not any(line.startswith(var) for var in contract_vars)
        and not line.startswith("❌")
        and "=" in line
    ]

    # Add contract lines to env_lines
    env_lines.extend(contract_lines)

    # Add required variables if not present
    for var, default_value in required_vars.items():
        if not any(line.startswith(f"{var}=") for line in env_lines):
            env_lines.append(f"{var}={default_value}")

    # Write the updated main .env file
    with open(env_path, "w") as f:
        for line in env_lines:
            f.write(f"{line}\n")

    print(f"✅ Updated {env_path} with configuration variables and contract addresses")


if __name__ == "__main__":
    main()
