import json

def load_abi(file_path):
    with open(file_path, "r") as file:
        data = json.load(file)
        return data["abi"]  # Extract only the ABI field

class LoadABI:
    @staticmethod
    def get_allocation_manager_abi():
        return load_abi("../../eigensdk/contracts/ABI/AllocationManager.json")

    @staticmethod
    def get_avs_directory_abi():
        return load_abi("../../eigensdk/contracts/ABI/AVSDirectory.json")

    @staticmethod
    def get_delegation_manager_abi():
        return load_abi("../../eigensdk/contracts/ABI/DelegationManager.json")

    @staticmethod
    def get_permission_control_abi():
        return load_abi("../../eigensdk/contracts/ABI/PermissionController.json")

    @staticmethod
    def get_strategy_manager_abi():
        return load_abi("../../eigensdk/contracts/ABI/StrategyManager.json")

    @staticmethod
    def get_rewards_coordinator_abi():
        return load_abi("../../eigensdk/contracts/ABI/RewardsCoordinator.json")

    @staticmethod
    def get_ierc20_abi():
        return load_abi("../../eigensdk/contracts/ABI/IERC20.json")

    @staticmethod
    def get_istrategy_abi():
        return load_abi("../../eigensdk/contracts/ABI/IStrategy.json")
