import json
import os


def load_abi(file_name):
    base_dir = os.path.dirname(__file__)
    abi_dir = os.path.join(base_dir, "ABI")
    abi_path = os.path.join(abi_dir, file_name)

    if not os.path.exists(abi_path):
        raise FileNotFoundError(f"ABI file not found: {abi_path}")

    with open(abi_path, "r") as file:
        data = json.load(file)
        return data["abi"]


ALLOCATION_MANAGER_ABI = load_abi("AllocationManager.json")
AVS_DIRECTORY_ABI = load_abi("AVSDirectory.json")
BLS_APK_REGISTRY_ABI = load_abi("BLSApkRegistry.json")
DELEGATION_MANAGER_ABI = load_abi("DelegationManager.json")
IERC20_ABI = load_abi("IERC20.json")
I_STRATEGY_ABI = load_abi("IStrategy.json")
OPERATOR_STATE_RETRIEVER_ABI = load_abi("OperatorStateRetriever.json")
PERMISSION_CONTROLLER_ABI = load_abi("PermissionController.json")
REGISTRY_COORDINATOR_ABI = load_abi("RegistryCoordinator.json")
REWARDS_COORDINATOR_ABI = load_abi("RewardsCoordinator.json")
SERVICE_MANAGER_BASE_ABI = load_abi("ServiceManagerBase.json")
STAKE_REGISTRY_ABI = load_abi("StakeRegistry.json")
STRATEGY_MANAGER_ABI = load_abi("StrategyManager.json")
