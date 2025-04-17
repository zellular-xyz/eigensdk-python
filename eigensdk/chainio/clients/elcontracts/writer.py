import logging
from enum import IntEnum
from eth_typing import Address
from typing import List, Any, Dict, cast
from web3 import Web3
from web3.contract import Contract
from eigensdk._types import Operator
from eigensdk.chainio.utils import abi_encode_registration_params, get_pubkey_registration_params


class RegistrationType(IntEnum):
    NORMAL = 0
    TRUSTED = 1


class ELWriter:
    def __init__(
        self,
        allocation_manager: Contract,
        avs_directory: Contract,
        delegation_manager: Contract,
        permission_controller: Contract,
        reward_coordinator: Contract,
        registry_coordinator: Contract,
        strategy_manager: Contract,
        strategy_manager_addr: Address,
        el_chain_reader: Any,
        eth_client: Web3,
        logger: logging.Logger,
        tx_mgr: Any,
        strategy_abi: List[Dict[str, Any]],
        erc20_abi: List[Dict[str, Any]],
    ):
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permission_controller = permission_controller
        self.rewards_coordinator = reward_coordinator
        self.registry_coordinator = registry_coordinator
        self.strategy_manager = strategy_manager
        self.strategy_manager_addr = strategy_manager_addr
        self.eth_client = eth_client
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi
        self.tx_mgr = tx_mgr
        self.el_chain_reader = el_chain_reader

        if allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        if avs_directory is None:
            raise ValueError("AvsDirectory contract not provided")

        if delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        if permission_controller is None:
            raise ValueError("PermissionController contract not provided")

        if reward_coordinator is None:
            raise ValueError("RewardCoordinator contract not provided")

        if strategy_manager is None:
            raise ValueError("StrategyManager contract not provided")

    def send(self, tx_func, *args, wait_for_receipt: bool = True):
        tx = tx_func(*args).build_transaction(self.tx_mgr.get_no_send_tx_opts())
        return self.tx_mgr.send(tx, wait_for_receipt)

    def register_as_operator(self, operator: Operator, wait_for_receipt: bool):
        return self.send(
            self.delegation_manager.functions.registerAsOperator,
            Web3.to_checksum_address(operator.delegation_approver_address),
            operator.allocation_delay,
            operator.metadata_url,
            wait_for_receipt=wait_for_receipt,
        )

    def update_operator_details(self, operator: Operator, wait_for_receipt: bool):
        return self.send(
            self.delegation_manager.functions.modifyOperatorDetails,
            Web3.to_checksum_address(operator.address),
            Web3.to_checksum_address(operator.delegation_approver_address),
            wait_for_receipt=wait_for_receipt,
        )

    def update_metadata_uri(self, operator_address: str, uri: str, wait_for_receipt: bool):
        return self.send(
            self.delegation_manager.functions.updateOperatorMetadataURI,
            Web3.to_checksum_address(operator_address),
            uri,
            wait_for_receipt=wait_for_receipt,
        )

    def deposit_erc20_into_strategy(self, strategy_addr: str, amount: int, wait_for_receipt: bool):
        _, token_contract, token_addr = (
            self.el_chain_reader.get_strategy_and_underlying_erc20_token(strategy_addr)
        )
        self.send(
            token_contract.functions.approve,
            self.strategy_manager.address,
            amount,
            wait_for_receipt=wait_for_receipt,
        )
        return self.send(
            self.strategy_manager.functions.depositIntoStrategy,
            Web3.to_checksum_address(strategy_addr),
            Web3.to_checksum_address(token_addr),
            amount,
            wait_for_receipt=wait_for_receipt,
        )

    def set_claimer_for(self, claimer: str, wait_for_receipt: bool):
        return self.send(
            self.rewards_coordinator.functions.setClaimerFor,
            Web3.to_checksum_address(claimer),
            wait_for_receipt=wait_for_receipt,
        )

    def process_claim(self, claim: dict, recipient_address: str, wait_for_receipt: bool):
        return self.send(
            self.rewards_coordinator.functions.processClaim,
            claim,
            Web3.to_checksum_address(recipient_address),
            wait_for_receipt=wait_for_receipt,
        )

    def set_operator_avs_split(self, operator: str, avs: str, split: int, wait_for_receipt: bool):
        return self.send(
            self.rewards_coordinator.functions.setOperatorAVSSplit,
            Web3.to_checksum_address(operator),
            Web3.to_checksum_address(avs),
            split,
            wait_for_receipt=wait_for_receipt,
        )

    def set_operator_pi_split(self, operator: str, split: int, wait_for_receipt: bool):
        return self.send(
            self.rewards_coordinator.functions.setOperatorPISplit,
            Web3.to_checksum_address(operator),
            split,
            wait_for_receipt=wait_for_receipt,
        )

    def set_operator_set_split(
        self, operator: str, operator_set: dict, split: int, wait_for_receipt: bool
    ):
        return self.send(
            self.rewards_coordinator.functions.setOperatorSetSplit,
            Web3.to_checksum_address(operator),
            operator_set,
            split,
            wait_for_receipt=wait_for_receipt,
        )

    def process_claims(self, claims: list, recipient_address: str, wait_for_receipt: bool):
        return self.send(
            self.rewards_coordinator.functions.processClaims,
            claims,
            Web3.to_checksum_address(recipient_address),
            wait_for_receipt=wait_for_receipt,
        )

    def modify_allocations(self, operator_address: str, allocations: list, wait_for_receipt: bool):
        return self.send(
            self.allocation_manager.functions.modifyAllocations,
            Web3.to_checksum_address(operator_address),
            allocations,
            wait_for_receipt=wait_for_receipt,
        )

    def clear_deallocation_queue(
        self, operator_address: str, strategies: list, nums_to_clear: list, wait_for_receipt: bool
    ):
        return self.send(
            self.allocation_manager.functions.clearDeallocationQueue,
            Web3.to_checksum_address(operator_address),
            [Web3.to_checksum_address(s) for s in strategies],
            nums_to_clear,
            wait_for_receipt=wait_for_receipt,
        )

    def set_allocation_delay(self, operator_address: str, delay: int, wait_for_receipt: bool):
        return self.send(
            self.allocation_manager.functions.setAllocationDelay,
            Web3.to_checksum_address(operator_address),
            delay,
            wait_for_receipt=wait_for_receipt,
        )

    def deregister_from_operator_sets(self, operator: str, request: dict):
        return self.send(
            self.allocation_manager.functions.deregisterFromOperatorSets,
            {
                "operator": Web3.to_checksum_address(operator),
                "avs": Web3.to_checksum_address(request["avs_address"]),
                "operatorSetIds": request["operator_set_ids"],
            },
            wait_for_receipt=request["wait_for_receipt"],
        )

    def register_for_operator_sets(self, registry_coordinator_addr: str, request: dict):
        return self.send(
            self.allocation_manager.functions.registerForOperatorSets,
            Web3.to_checksum_address(request["operator_address"]),
            {
                "avs": Web3.to_checksum_address(request["avs_address"]),
                "operatorSetIds": request["operator_set_ids"],
                "data": abi_encode_registration_params(
                    RegistrationType.NORMAL,  # ✅ FIXED
                    request["socket"],
                    get_pubkey_registration_params(
                        self.eth_client,
                        cast(Address, Web3.to_checksum_address(registry_coordinator_addr)),
                        cast(Address, Web3.to_checksum_address(request["operator_address"])),
                        request["bls_key_pair"],
                    ),
                ),
            },
            wait_for_receipt=request["wait_for_receipt"],
        )

    def remove_permission(self, request: dict):
        return self.send(
            self.permission_controller.functions.removeAppointee,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
            wait_for_receipt=request["wait_for_receipt"],
        )

    def new_remove_permission_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.removeAppointee,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
            wait_for_receipt=request.get("wait_for_receipt", True),
        )

    def new_set_permission_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.setAppointee,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
            wait_for_receipt=request.get("wait_for_receipt", True),
        )

    def set_permission(self, request: dict):
        return self.send(
            self.permission_controller.functions.setAppointee,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
            wait_for_receipt=request["wait_for_receipt"],
        )

    def new_accept_admin_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.acceptAdmin,
            Web3.to_checksum_address(request["account_address"]),
            wait_for_receipt=request.get("wait_for_receipt", True),
        )

    def accept_admin(self, request: dict):
        return self.send(
            self.permission_controller.functions.acceptAdmin,
            Web3.to_checksum_address(request["account_address"]),
            wait_for_receipt=request["wait_for_receipt"],
        )

    def add_pending_admin(self, request: dict):
        return self.send(
            self.permission_controller.functions.addPendingAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request["wait_for_receipt"],
        )

    def new_remove_admin_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.removeAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request.get("wait_for_receipt", True),
        )

    def remove_admin(self, request: dict):
        return self.send(
            self.permission_controller.functions.removeAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request["wait_for_receipt"],
        )

    def new_remove_pending_admin_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.removePendingAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request.get("wait_for_receipt", True),
        )

    def remove_pending_admin(self, request: dict):
        return self.send(
            self.permission_controller.functions.removePendingAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request["wait_for_receipt"],
        )

    def new_add_pending_admin_tx(self, tx_opts, request: dict):
        return self.send(
            self.permission_controller.functions.addPendingAdmin,
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
            wait_for_receipt=request.get("wait_for_receipt", True),
        )
