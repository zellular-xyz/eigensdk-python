import logging
from enum import IntEnum
from typing import List, Any, Dict

from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract import Contract
from web3.contract.contract import ContractFunction
from web3.types import ChecksumAddress
from web3.types import TxReceipt

from eigensdk.chainio.utils import (
    abi_encode_normal_registration_params,
    get_pubkey_registration_params,
    Transactor,
)
from eigensdk.types_ import Operator


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
        el_chain_reader: Any,
        eth_http_client: Web3,
        logger: logging.Logger,
        pk_wallet: LocalAccount,
        strategy_abi: List[Dict[str, Any]],
        erc20_abi: List[Dict[str, Any]],
    ):
        """Initialize the ELWriter with contract instances and configuration."""
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permission_controller = permission_controller
        self.rewards_coordinator = reward_coordinator
        self.registry_coordinator = registry_coordinator
        self.strategy_manager = strategy_manager
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi
        self.el_chain_reader = el_chain_reader
        self.transactor = Transactor(pk_wallet, eth_http_client)

        if allocation_manager is None:
            self.logger.warning("AllocationManager contract not provided")

        if avs_directory is None:
            self.logger.warning("AvsDirectory contract not provided")

        if delegation_manager is None:
            self.logger.warning("DelegationManager contract not provided")

        if permission_controller is None:
            self.logger.warning("PermissionController contract not provided")

        if reward_coordinator is None:
            self.logger.warning("RewardCoordinator contract not provided")

        if registry_coordinator is None:
            self.logger.warning("RegistryCoordinator contract not provided")

        if strategy_manager is None:
            self.logger.warning("StrategyManager contract not provided")

        if el_chain_reader is None:
            self.logger.warning("ELChainReader contract not provided")

        if eth_http_client is None:
            self.logger.warning("EthHTTPClient not provided")

        if pk_wallet is None:
            self.logger.warning("PKWallet not provided")

        if strategy_abi is None:
            self.logger.warning("StrategyABI not provided")

        if erc20_abi is None:
            self.logger.warning("ERC20ABI not provided")

    def send_transaction(self, func: ContractFunction):
        """Send a transaction using the configured transactor."""
        return self.transactor.send(func)

    def register_as_operator(self, operator: Operator) -> TxReceipt:
        """Registers the caller as an operator in EigenLayer through the DelegationManager
        contract."""
        func = self.delegation_manager.functions.registerAsOperator(
            operator.delegation_approver_address,
            operator.allocation_delay,
            operator.metadata_url,
        )
        return self.send_transaction(func)

    def update_operator_details(self, operator: Operator) -> TxReceipt:
        """Updates an operator's stored delegationApprover with the given
        operator.DelegationApproverAddress by calling modifyOperatorDetails."""
        func = self.delegation_manager.functions.modifyOperatorDetails(
            operator.address,
            operator.delegation_approver_address,
        )
        return self.send_transaction(func)

    def update_metadata_uri(self, operator_address: str, uri: str) -> TxReceipt:
        """Updates the metadata URI for the given operator."""
        func = self.delegation_manager.functions.updateOperatorMetadataURI(
            Web3.to_checksum_address(operator_address),
            uri,
        )
        return self.send_transaction(func)

    def deposit_erc20_into_strategy(self, strategy_addr: str, amount: int) -> TxReceipt:
        """Deposits amount of the strategyAddr underlying token into the strategy given by
        strategyAddr."""
        _, token_contract, token_addr = (
            self.el_chain_reader.get_strategy_and_underlying_erc20_token(strategy_addr)
        )
        func = token_contract.functions.approve(
            self.strategy_manager.address,
            amount,
        )
        self.send_transaction(func)
        func = self.strategy_manager.functions.depositIntoStrategy(
            Web3.to_checksum_address(strategy_addr),
            Web3.to_checksum_address(token_addr),
            amount,
        )
        return self.send_transaction(func)

    def set_claimer_for(self, claimer: str) -> TxReceipt:
        """Sets claimer as the claimer for the earner (caller).

        Enables claimer to call processClaim.
        """
        func = self.rewards_coordinator.functions.setClaimerFor(
            Web3.to_checksum_address(claimer),
        )
        return self.send_transaction(func)

    def process_claim(self, claim: dict, recipient_address: str) -> TxReceipt:
        """Processes the given claim for rewards.

        Transfers rewards to recipientAddress.
        """
        claim_tuple = (
            claim["rootIndex"],
            claim["earnerIndex"],
            claim["earnerTreeProof"],
            (  # earnerLeaf (tuple)
                Web3.to_checksum_address(claim["earnerLeaf"]["earner"]),
                claim["earnerLeaf"]["earnerTokenRoot"],
            ),
            claim["tokenIndices"],  # list of uint32
            claim["tokenTreeProofs"],  # list of bytes
            [
                (Web3.to_checksum_address(tl["token"]), int(tl["cumulativeEarnings"]))
                for tl in claim["tokenLeaves"]
            ],
        )

        func = self.rewards_coordinator.functions.processClaim(
            claim_tuple, Web3.to_checksum_address(recipient_address)
        )

        return self.send_transaction(func)

    def set_operator_avs_split(self, operator: str, avs: str, split: int) -> TxReceipt:
        """Sets the split for a specific operator for a specific AVS.

        Must be between 0 and 10000 bips. Activated after delay.
        """
        func = self.rewards_coordinator.functions.setOperatorAVSSplit(
            Web3.to_checksum_address(operator),
            Web3.to_checksum_address(avs),
            split,
        )

        return self.send_transaction(func)

    def set_operator_pi_split(self, operator: str, split: int) -> TxReceipt:
        """Sets the split for a specific operator for Programmatic Incentives.

        Must be between 0 and 10000 bips. Activated after delay.
        """
        func = self.rewards_coordinator.functions.setOperatorPISplit(
            Web3.to_checksum_address(operator),
            split,
        )

        return self.send_transaction(func)

    def modify_allocations(
        self,
        operator_address: str,
        avs_service_manager: str,
        operator_set_id: int,
        strategies: list,
        new_magnitudes: list,
    ) -> TxReceipt:
        """Modifies proportions of slashable stake allocated to an operator set from a list of
        strategies."""
        allocation = (
            (Web3.to_checksum_address(avs_service_manager), operator_set_id),
            [Web3.to_checksum_address(s) for s in strategies],
            new_magnitudes,
        )

        func = self.allocation_manager.functions.modifyAllocations(
            Web3.to_checksum_address(operator_address), [allocation]
        )

        return self.send_transaction(func)

    def clear_deallocation_queue(
        self, operator_address: str, strategies: list, nums_to_clear: list
    ) -> TxReceipt:
        """Clears an operator's deallocation queue for specific strategies.

        Ensures queues are in sync with effect timestamps.
        """
        func = self.allocation_manager.functions.clearDeallocationQueue(
            Web3.to_checksum_address(operator_address),
            [Web3.to_checksum_address(s) for s in strategies],
            nums_to_clear,
        )

        return self.send_transaction(func)

    def set_allocation_delay(self, operator_address: str, delay: int) -> TxReceipt:
        """Sets the allocation delay for an operator.

        Defines blocks before allocated stake becomes slashable.
        """
        func = self.allocation_manager.functions.setAllocationDelay(
            Web3.to_checksum_address(operator_address),
            delay,
        )

        return self.send_transaction(func)

    def deregister_from_operator_sets(self, operator: str, request: dict) -> TxReceipt:
        """Deregisters an operator from AVS operator sets.

        Remaining slashable stake remains until delay elapses.
        """
        func = self.allocation_manager.functions.deregisterFromOperatorSets(
            {
                "operator": Web3.to_checksum_address(operator),
                "avs": Web3.to_checksum_address(request["avs_address"]),
                "operatorSetIds": request["operator_set_ids"],
            }
        )

        return self.send_transaction(func)

    def register_for_operator_sets(
        self, registry_coordinator_addr: str, request: dict
    ) -> TxReceipt:
        """Registers an operator for operator sets.

        If churnApprovalEcdsaPrivateKey is provided, it replaces in full quorums.
        """
        pubkey_reg_params = get_pubkey_registration_params(
            self.transactor.eth_http_client,
            Web3.to_checksum_address(registry_coordinator_addr),
            Web3.to_checksum_address(request["operator_address"]),
            request["bls_key_pair"],
        )

        encoded_data = abi_encode_normal_registration_params(
            RegistrationType.NORMAL,
            request["socket"],
            pubkey_reg_params,
        )

        register_params = {
            "avs": Web3.to_checksum_address(request["avs_address"]),
            "operatorSetIds": request["operator_set_ids"],
            "data": encoded_data,
        }

        func = self.allocation_manager.functions.registerForOperatorSets(
            Web3.to_checksum_address(request["operator_address"]),
            register_params,
        )

        return self.send_transaction(func)

    def remove_permission(self, request: dict) -> TxReceipt:
        """Removes permission of an appointee for a specific function on a contract, for an
        account."""
        func = self.permission_controller.functions.removeAppointee(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
        )

        return self.send_transaction(func)

    def set_permission(self, request: dict) -> TxReceipt:
        """Sets an appointee for an account.

        Only admins can assign appointees to functions.
        """
        func = self.permission_controller.functions.setAppointee(
            Web3.to_checksum_address(request["account_address"].lower()),
            Web3.to_checksum_address(request["appointee_address"].lower()),
            Web3.to_checksum_address(request["target"].lower()),
            request["selector"],
        )
        return self.send_transaction(func)

    def accept_admin(self, request: dict) -> TxReceipt:
        """Accepts pending admin role for the account.

        Caller must be the pending admin.
        """
        func = self.permission_controller.functions.acceptAdmin(
            Web3.to_checksum_address(request["account_address"]),
        )

        return self.send_transaction(func)

    def add_pending_admin(self, request: dict) -> TxReceipt:
        """Sets a pending admin.

        Admins can add others. If none exist, account can self-assign.
        """
        func = self.permission_controller.functions.addPendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )

        return self.send_transaction(func)

    def remove_admin(self, request: dict) -> TxReceipt:
        """Removes the admin from an account.

        Caller must be an existing admin.
        """
        func = self.permission_controller.functions.removeAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )
        return self.send_transaction(func)

    def remove_pending_admin(self, request: dict) -> TxReceipt:
        """Removes a pending admin from an account.

        Only current admin can perform this.
        """
        func = self.permission_controller.functions.removePendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )

        return self.send_transaction(func)

    def get_operator_id(self, operator_address: ChecksumAddress) -> bytes:
        """Returns the operator ID for the given operator address."""
        return self.registry_coordinator.functions.getOperatorId(operator_address).call()

    def set_avs_registrar(self, avs_address: str, registrar_address: str) -> TxReceipt:
        """Sets the avsRegistrar for the received AVS, typically a RegistryCoordinator."""
        func = self.allocation_manager.functions.setAVSRegistrar(
            Web3.to_checksum_address(avs_address),
            Web3.to_checksum_address(registrar_address),
        )
        return self.send_transaction(func)
