import logging
from typing import Tuple, List, Any, Dict, Optional

from eth_typing import Address
from web3 import Web3
from web3.contract import Contract
from eigensdk._types import Operator
from eigensdk.contracts import ABIs
from eigensdk.chainio import chainio_utils as utils

from typeguard import typechecked


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

        if strategy_abi is None:
            raise ValueError("Strategy ABI not provided")

        if erc20_abi is None:
            raise ValueError("ERC20 ABI not provided")

    
    def register_as_operator(self, operator, wait_for_receipt: bool):
        self.logger.info(f"Registering operator {operator.address} to EigenLayer")

        tx = self.delegation_manager.functions.registerAsOperator(
            Web3.to_checksum_address(operator.delegation_approver_address),
            operator.allocation_delay,
            operator.metadata_url,
        ).build_transaction(self.tx_mgr.get_no_send_tx_opts())

        return self.tx_mgr.send(tx, wait_for_receipt)

    
    def register_as_operator_pre_slashing(
            self, operator: Dict[str, Any], wait_for_receipt: bool
        ) -> Optional[Dict]:
        contract = self.eth_client.eth.contract(
            address=self.delegation_manager_addr,
            abi=self.delegation_manager_abi
        )

        tx = contract.functions.registerAsOperator(
            self.tx_mgr.get_no_send_tx_opts(),
            {
                "deprecatedEarningsReceiver": Web3.to_checksum_address(operator["Address"]),
                "stakerOptOutWindowBlocks": operator["StakerOptOutWindowBlocks"],
                "delegationApprover": Web3.to_checksum_address(operator["DelegationApproverAddress"]),
            },
            operator["MetadataUrl"],
        ).build_transaction()

        return self.tx_mgr.send(tx, wait_for_receipt)


    
    def update_operator_details(self, operator, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.delegation_manager.functions.modifyOperatorDetails(
                Web3.to_checksum_address(operator.address),
                Web3.to_checksum_address(operator.delegation_approver_address),
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )


    
    def update_metadata_uri(self, operator_address: str, uri: str, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.delegation_manager.functions.updateOperatorMetadataURI(
                Web3.to_checksum_address(operator_address), uri
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )


    
    def deposit_erc20_into_strategy(self, strategy_addr: str, amount: int, wait_for_receipt: bool):
        _, token_contract, token_addr = self.el_chain_reader.get_strategy_and_underlying_erc20_token(strategy_addr)

        approve_tx = token_contract.functions.approve(
            Web3.to_checksum_address(self.strategy_manager.address),
            amount
        ).build_transaction(self.tx_mgr.get_no_send_tx_opts())

        self.tx_mgr.send(approve_tx, wait_for_receipt)

        return self.tx_mgr.send(
            self.strategy_manager.functions.depositIntoStrategy(
                Web3.to_checksum_address(strategy_addr),
                Web3.to_checksum_address(token_addr),
                amount,
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )


    
    def set_claimer_for(self, claimer: str, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.setClaimerFor(
                Web3.to_checksum_address(claimer)
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def process_claim(self, claim: dict, recipient_address: str, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.processClaim(
                claim, Web3.to_checksum_address(recipient_address)
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def set_operator_avs_split(self, operator: str, avs: str, split: int, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.setOperatorAVSSplit(
                Web3.to_checksum_address(operator), Web3.to_checksum_address(avs), split
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def set_operator_pi_split(self, operator: str, split: int, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.setOperatorPISplit(
                Web3.to_checksum_address(operator), split
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def set_operator_set_split(
        self, operator: str, operator_set: dict, split: int, wait_for_receipt: bool
    ):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.setOperatorSetSplit(
                Web3.to_checksum_address(operator), operator_set, split
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def process_claims(self, claims: list, recipient_address: str, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.rewards_coordinator.functions.processClaims(
                claims, Web3.to_checksum_address(recipient_address)
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def modify_allocations(self, operator_address: str, allocations: list, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.allocation_manager.functions.modifyAllocations(
                Web3.to_checksum_address(operator_address), allocations
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def clear_deallocation_queue(
        self, operator_address: str, strategies: list, nums_to_clear: list, wait_for_receipt: bool
    ):
        return self.tx_mgr.send(
            self.allocation_manager.functions.clearDeallocationQueue(
                Web3.to_checksum_address(operator_address),
                [Web3.to_checksum_address(s) for s in strategies],
                nums_to_clear,
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def set_allocation_delay(self, operator_address: str, delay: int, wait_for_receipt: bool):
        return self.tx_mgr.send(
            self.allocation_manager.functions.setAllocationDelay(
                Web3.to_checksum_address(operator_address), delay
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            wait_for_receipt,
        )

    
    def deregister_from_operator_sets(self, operator: str, request: dict):
        return self.tx_mgr.send(
            self.allocation_manager.functions.deregisterFromOperatorSets(
                {
                    "operator": Web3.to_checksum_address(operator),
                    "avs": Web3.to_checksum_address(request["avs_address"]),
                    "operatorSetIds": request["operator_set_ids"],
                }
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            request["wait_for_receipt"],
        )

    
    def register_for_operator_sets(self, registry_coordinator_addr: str, request: dict):
        op_addr = Web3.to_checksum_address(request["operator_address"])
        avs_addr = Web3.to_checksum_address(request["avs_address"])
        coord_addr = Web3.to_checksum_address(registry_coordinator_addr)

        pubkey_params = utils.get_pubkey_registration_params(
            self.eth_client, coord_addr, op_addr, request["bls_key_pair"]
        )
        encoded_data = utils.abi_encode_registration_params(
            "RegistrationTypeNormal", request["socket"], pubkey_params
        )

        return self.tx_mgr.send(
            self.allocation_manager.functions.registerForOperatorSets(
                op_addr,
                {
                    "avs": avs_addr,
                    "operatorSetIds": request["operator_set_ids"],
                    "data": encoded_data,
                },
            ).build_transaction(self.tx_mgr.get_no_send_tx_opts()),
            request["wait_for_receipt"],
        )

    
    def remove_permission(self, request: dict):
        return self.tx_mgr.send(
            self.new_remove_permission_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def new_remove_permission_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.removeAppointee(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
        ).build_transaction(tx_opts)

    
    def new_set_permission_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.setAppointee(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
        ).build_transaction(tx_opts)

    
    def set_permission(self, request: dict):
        return self.tx_mgr.send(
            self.new_set_permission_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def new_accept_admin_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.acceptAdmin(
            Web3.to_checksum_address(request["account_address"])
        ).build_transaction(tx_opts)

    
    def accept_admin(self, request: dict):

        return self.tx_mgr.send(
            self.new_accept_admin_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def add_pending_admin(self, request: dict):
        return self.tx_mgr.send(
            self.new_add_pending_admin_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def new_remove_admin_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.removeAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        ).build_transaction(tx_opts)

    
    def remove_admin(self, request: dict):
        return self.tx_mgr.send(
            self.new_remove_admin_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def new_remove_pending_admin_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.removePendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        ).build_transaction(tx_opts)

    
    def remove_pending_admin(self, request: dict):
        return self.tx_mgr.send(
            self.new_remove_pending_admin_tx(self.tx_mgr.get_no_send_tx_opts(), request),
            request["wait_for_receipt"],
        )

    
    def new_add_pending_admin_tx(self, tx_opts, request: dict):
        return self.permission_controller.functions.addPendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        ).build_transaction(tx_opts)
