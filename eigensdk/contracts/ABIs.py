import json

def load_abi(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
        return data["abi"]  # Extract only the ABI field

ALLOCATION_MANAGER_ABI = load_abi("../../eigensdk/contracts/ABI/AllocationManager.json")
AVS_DIRECTORY_ABI = load_abi("../../eigensdk/contracts/ABI/AVSDirectory.json")
DELEGATION_MANAGER_ABI = load_abi("../../eigensdk/contracts/ABI/DelegationManager.json")
PERMISSION_CONTROL_ABI = load_abi("../../eigensdk/contracts/ABI/PermissionController.json")
STRATEGY_MANAGER_ABI = load_abi("../../eigensdk/contracts/ABI/StrategyManager.json")
REWARDS_COORDINATOR_ABI = load_abi("../../eigensdk/contracts/ABI/RewardsCoordinator.json")
IERC20_ABI = load_abi("../../eigensdk/contracts/ABI/IERC20.json")
IStrategy_ABI = load_abi("../../eigensdk/contracts/ABI/IStrategy.json")