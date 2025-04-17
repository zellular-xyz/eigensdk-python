#!/usr/bin/env python3
import json
from pathlib import Path

DEFAULT_CONTRACTS = [
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

DEFAULTS = {
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

MAPPING = {
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


def get_contract_addresses():
    d = Path("/app/eigenlayer-contracts/broadcast")
    if not d.exists(): return DEFAULT_CONTRACTS
    f = sorted(d.glob("**/run-latest.json"), key=lambda x: x.stat().st_mtime, reverse=True)[0]
    c = {t["contractName"]: t["contractAddress"] for t in json.load(open(f)).get("transactions", []) if t.get("transactionType") == "CREATE"}
    return [f"{v}={c[k]}" for k, v in MAPPING.items() if k in c]


def main():
    env_lines = get_contract_addresses()
    env_lines += [f"{k}={v}" for k, v in DEFAULTS.items()]
    open("tests/.env", "w").write("\n".join(env_lines) + "\n")
    print("✅ Env created with configuration variables and contract addresses")

if __name__ == "__main__":
    main()
