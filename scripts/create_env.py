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
        "ANVIL_SENDER_ADDRESS": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "ANVIL_PRIVATE_KEY": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "ANVIL_ETH_HTTP_URL": "http://anvil:8545",
        "HOLESKY_SENDER_ADDRESS":"",
        "HOLESKY_PRIVATE_KEY":"",
        "HOLESKY_ETH_HTTP_URL":"",
        "AVS_NAME": "Zellular",
        "PROM_METRICS_IP_PORT_ADDRESS": "localhost:9090",
        "IERC20_ADDR": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
        "ISTRATEGY_ADDR": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
        "HOLESKY_STRATEGY_MANAGER_ADDR":"0xd634f0a12a1c640487384bc173783b0ec951fe62",
        "HOLESKY_DELEGATION_MANAGER_ADDR":"0xb92919c60b2ceadbe8c1c627a926298f1c1c66f6",
        "HOLESKY_AVS_DIRECTORY_ADDR":"0x893c170d6025701baf28f02775dbec8342bb97c9",
        "HOLESKY_REGISTRY_COORDINATOR_ADDR":"0xC908fAFAE29B5C9F0b5E0Da1d3025b8d6D42bfa0",   
        "HOLESKY_STAKE_REGISTRY_ADDR":"0xa8d25410c3e3347d93647f10FB6961069BEc98E5",    
        "HOLESKY_SERVICE_MANAGER_ADDR":"0xa7227485e6C693AC4566fe168C5E3647c5c267f3",    
        "HOLESKY_BLS_APK_REGISTRY_ADDR":"0x885C0CC8118E428a2C04de58A93eB15Ed4F0e064",    
        "HOLESKY_OPERATOR_STATE_RETRIEVER_ADDR":"0xB4baAfee917fb4449f5ec64804217bccE9f46C67",    
        "HOLESKY_ALLOCATION_MANAGER_ADDR":"0x9fe131fb3957fa8615c5ff68c374f60087f188a3",
        "HOLESKY_PERMISSION_CONTROL_ADDR":"0xcb2685b42df58483547a726d42c061f703cd124f",
        "HOLESKY_REWARDS_COORDINATOR_ADDR":"0x07faca686c86f749edfecafbdb154f80cbfdfca4",
        "HOLESKY_STRATEGY_ADDR":"0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"
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
    
    # Ensure the tests directory exists
    tests_dir = Path("tests")
    tests_dir.mkdir(exist_ok=True)
    
    # Create the .env file
    env_file = tests_dir / ".env"
    env_file.write_text("\n".join(env_lines) + "\n")
    print(f"✅ Env created at {env_file.absolute()} with configuration variables and contract addresses")

if __name__ == "__main__":
    main()