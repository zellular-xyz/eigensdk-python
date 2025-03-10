import logging
from typing import Tuple, List, Any, Dict, Optional

from eth_typing import Address
from web3 import Web3
from web3.contract import Contract
from eigensdk._types import Operator
from eigensdk.contracts import ABIs
from eigensdk.chainio.clients.elcontracts.utils import get_pubkey_registration_params, abi_encode_registration_params

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
        logger: logging.Logger,
        eth_http_client: Web3,
        strategy_abi: List[Dict[str, Any]],
        erc20_abi: List[Dict[str, Any]],
        tx_mgr: Any,
        el_chain_reader: Any,
    ):
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permission_controller = permission_controller
        self.rewards_coordinator = reward_coordinator
        self.registry_coordinator = registry_coordinator
        self.strategy_manager = strategy_manager
        self.eth_http_client = eth_http_client
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi
        self.tx_mgr = tx_mgr
        self.el_chain_reader = el_chain_reader

    def register_as_operator(self, operator, wait_for_receipt: bool):
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        self.logger.info(f"Registering operator {operator.address} to EigenLayer")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            return None, e

        try:
            tx = self.delegation_manager.functions.registerAsOperator(
                Web3.to_checksum_address(operator.delegation_approver_address),
                operator.allocation_delay,
                operator.metadata_url,
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send tx: %s", str(e))
            return None, e

        self.logger.info(f"Transaction successfully included: txHash {receipt.transactionHash.hex()}")

        return receipt


    def update_operator_details(self, operator, wait_for_receipt: bool):
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        self.logger.info(f"Updating operator details of operator {operator.address} to EigenLayer")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            return None, e

        try:
            tx = self.delegation_manager.functions.modifyOperatorDetails(
                Web3.to_checksum_address(operator.address),
                Web3.to_checksum_address(operator.delegation_approver_address),
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        self.logger.info(
            f"Successfully updated operator details | txHash: {receipt.transactionHash.hex()} | operator: {operator.address}"
        )

        return receipt


    def update_metadata_uri(self, operator_address: str, uri: str, wait_for_receipt: bool):
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            return None, e

        try:
            tx = self.delegation_manager.functions.updateOperatorMetadataURI(
                Web3.to_checksum_address(operator_address),
                uri
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        self.logger.info(f"Successfully updated operator metadata URI | txHash: {receipt.transactionHash.hex()}")

        return receipt


    def deposit_erc20_into_strategy(self, strategy_addr: str, amount: int, wait_for_receipt: bool):
        if self.strategy_manager is None:
            raise ValueError("StrategyManager contract not provided")

        self.logger.info(f"Depositing {amount} tokens into strategy {strategy_addr}")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            return None, e

        try:
            _, underlying_token_contract, underlying_token_addr = self.el_chain_reader.get_strategy_and_underlying_erc20_token(
                strategy_addr
            )
        except Exception as e:
            return None, e

        try:
            tx = underlying_token_contract.functions.approve(
                Web3.to_checksum_address(self.strategy_manager.address),
                amount
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to approve token transfer: %s", str(e))
            return None, e

        try:
            _, _ = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            return None, e

        try:
            tx = self.strategy_manager.functions.depositIntoStrategy(
                Web3.to_checksum_address(strategy_addr),
                Web3.to_checksum_address(underlying_token_addr),
                amount
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send tx: %s", str(e))
            return None, e

        self.logger.info(f"Deposited {amount} into strategy {strategy_addr}")
        return receipt


    def set_claimer_for(self, claimer: str, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            return None, e

        try:
            tx = self.rewards_coordinator.functions.setClaimerFor(
                Web3.to_checksum_address(claimer)
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def process_claim(self, claim: dict, recipient_address: str, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.rewards_coordinator.functions.processClaim(
                claim,
                Web3.to_checksum_address(recipient_address)
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create ProcessClaim transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def set_operator_avs_split(self, operator: str, avs: str, split: int, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.rewards_coordinator.functions.setOperatorAVSSplit(
                Web3.to_checksum_address(operator),
                Web3.to_checksum_address(avs),
                split
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create SetOperatorAVSSplit transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def set_operator_pi_split(self, operator: str, split: int, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.rewards_coordinator.functions.setOperatorPISplit(
                Web3.to_checksum_address(operator),
                split
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create SetOperatorPISplit transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def set_operator_set_split(self, operator: str, operator_set: dict, split: int, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.rewards_coordinator.functions.setOperatorSetSplit(
                Web3.to_checksum_address(operator),
                operator_set,
                split
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create SetOperatorSetSplit transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def process_claims(self, claims: list, recipient_address: str, wait_for_receipt: bool):
        if self.rewards_coordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        if not claims:
            raise ValueError("Claims list is empty, at least one claim must be provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.rewards_coordinator.functions.processClaims(
                claims,
                Web3.to_checksum_address(recipient_address)
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create ProcessClaims transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def modify_allocations(self, operator_address: str, allocations: list, wait_for_receipt: bool):
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.allocation_manager.functions.modifyAllocations(
                Web3.to_checksum_address(operator_address),
                allocations
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create ModifyAllocations transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt

    
    def clear_deallocation_queue(self, operator_address: str, strategies: list, nums_to_clear: list, wait_for_receipt: bool):
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.allocation_manager.functions.clearDeallocationQueue(
                Web3.to_checksum_address(operator_address),
                [Web3.to_checksum_address(strategy) for strategy in strategies],
                nums_to_clear
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create ClearDeallocationQueue transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def set_allocation_delay(self, operator_address: str, delay: int, wait_for_receipt: bool):
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.allocation_manager.functions.setAllocationDelay(
                Web3.to_checksum_address(operator_address),
                delay
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create SetAllocationDelay transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, wait_for_receipt)
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def deregister_from_operator_sets(self, operator: str, request: dict):
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.allocation_manager.functions.deregisterFromOperatorSets(
                {
                    "operator": Web3.to_checksum_address(operator),
                    "avs": Web3.to_checksum_address(request["avs_address"]),
                    "operatorSetIds": request["operator_set_ids"],
                }
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create DeregisterFromOperatorSets transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def register_for_operator_sets(self, registry_coordinator_addr: str, request: dict):
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no send tx opts: %s", str(e))
            return None, e

        try:
            pubkey_reg_params = get_pubkey_registration_params(
                self.eth_http_client,
                Web3.to_checksum_address(registry_coordinator_addr),
                Web3.to_checksum_address(request["operator_address"]),
                request["bls_key_pair"],
            )
        except Exception as e:
            self.logger.error("Failed to get public key registration params: %s", str(e))
            return None, e

        try:
            data = abi_encode_registration_params(
                "RegistrationTypeNormal",
                request["socket"],
                pubkey_reg_params
            )
        except Exception as e:
            self.logger.error("Failed to encode registration params: %s", str(e))
            return None, e

        try:
            tx = self.allocation_manager.functions.registerForOperatorSets(
                Web3.to_checksum_address(request["operator_address"]),
                {
                    "avs": Web3.to_checksum_address(request["avs_address"]),
                    "operatorSetIds": request["operator_set_ids"],
                    "data": data,
                }
            ).build_transaction(no_send_tx_opts)
        except Exception as e:
            self.logger.error("Failed to create RegisterForOperatorSets transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def remove_permission(self, request: dict):
        try:
            tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_remove_permission_tx(tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create NewRemovePermissionTx: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def new_remove_permission_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.removeAppointee(
                Web3.to_checksum_address(request["account_address"]),
                Web3.to_checksum_address(request["appointee_address"]),
                request["target"],
                request["selector"]
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewRemovePermissionTx: %s", str(e))
            return None, e

        return tx


    def new_set_permission_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.setAppointee(
                Web3.to_checksum_address(request["account_address"]),
                Web3.to_checksum_address(request["appointee_address"]),
                request["target"],
                request["selector"]
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewSetPermissionTx: %s", str(e))
            return None, e

        return tx

    def set_permission(self, request: dict):
        try:
            tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_set_permission_tx(tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create NewSetPermissionTx: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt

    def new_accept_admin_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.acceptAdmin(
                Web3.to_checksum_address(request["account_address"])
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewAcceptAdminTx: %s", str(e))
            return None, e

        return tx

    def accept_admin(self, request: dict):
        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_accept_admin_tx(no_send_tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create AcceptAdmin transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def add_pending_admin(self, request: dict):
        try:
            tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_add_pending_admin_tx(tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create AddPendingAdminTx: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt



    def new_remove_admin_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.removeAdmin(
                Web3.to_checksum_address(request["account_address"]),
                Web3.to_checksum_address(request["admin_address"])
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewRemoveAdminTx: %s", str(e))
            return None, e

        return tx


    def remove_admin(self, request: dict):
        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_remove_admin_tx(no_send_tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create RemoveAdmin transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def new_remove_pending_admin_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.removePendingAdmin(
                Web3.to_checksum_address(request["account_address"]),
                Web3.to_checksum_address(request["admin_address"])
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewRemovePendingAdminTx: %s", str(e))
            return None, e

        return tx


    def remove_pending_admin(self, request: dict):
        try:
            no_send_tx_opts = self.tx_mgr.get_no_send_tx_opts()
        except Exception as e:
            self.logger.error("Failed to get no-send tx opts: %s", str(e))
            return None, e

        try:
            tx = self.new_remove_pending_admin_tx(no_send_tx_opts, request)
        except Exception as e:
            self.logger.error("Failed to create RemovePendingAdmin transaction: %s", str(e))
            return None, e

        try:
            receipt = self.tx_mgr.send(tx, request["wait_for_receipt"])
        except Exception as e:
            self.logger.error("Failed to send transaction: %s", str(e))
            return None, e

        return receipt


    def new_add_pending_admin_tx(self, tx_opts, request: dict):
        if self.permission_controller is None:
            raise ValueError("Permission contract not provided")

        try:
            tx = self.permission_controller.functions.addPendingAdmin(
                Web3.to_checksum_address(request["account_address"]),
                Web3.to_checksum_address(request["admin_address"])
            ).build_transaction(tx_opts)
        except Exception as e:
            self.logger.error("Failed to create NewAddPendingAdminTx: %s", str(e))
            return None, e

        return tx