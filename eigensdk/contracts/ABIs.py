import json
 
def load_abi(file_path):

    with open(file_path, "r") as file:
        data = json.load(file)
        return data["abi"]  # Extract only the ABI field


# Provide ABI file paths (Replace with your ABI JSON file paths)
ALLOCATION_MANAGER_ABI = load_abi("./ABIs/AllocationManager.json")
AVS_DIRECTORY_ABI = load_abi("./ABIs/AVSDirectory.json")
DELEGATION_MANAGER_ABI = load_abi("./ABIs/DelegationManager.json")
PERMISSION_CONTROL_ABI = load_abi("./ABIs/PermissionController.json")
STRATEGY_MANAGER_ABI = load_abi("./ABIs/StrategyManager.json")
REWARDS_COORDINATOR_ABI = load_abi("./ABIs/RewardsCoordinator.json")
IERC20 = load_abi("./ABIs/IERC20.json")
ISTRATEGY = load_abi("./ABIs/IStrategy.json")