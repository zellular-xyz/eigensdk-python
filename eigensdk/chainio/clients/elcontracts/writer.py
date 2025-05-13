import logging
from enum import IntEnum
from typing import List, Any, Dict, cast

from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import Web3
from web3.contract import Contract
from web3.types import TxReceipt

from eigensdk._types import Operator
from eigensdk.chainio.utils import abi_encode_registration_params, get_pubkey_registration_params
from ...utils import send_transaction


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
        self.el_chain_reader = el_chain_reader
        self.pk_wallet: LocalAccount = pk_wallet

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

    def register_as_operator(self, operator: Operator) -> TxReceipt:
        delegation_approver = (
            Web3.to_checksum_address(operator.delegation_approver_address)
            if operator.delegation_approver_address is not None
            else "0x0000000000000000000000000000000000000000"
        )
        func = self.delegation_manager.functions.registerAsOperator(
            delegation_approver,
            operator.allocation_delay,
            operator.metadata_url,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def update_operator_details(self, operator: Operator) -> TxReceipt:
        func = self.delegation_manager.functions.modifyOperatorDetails(
            Web3.to_checksum_address(operator.address),
            Web3.to_checksum_address(operator.delegation_approver_address),
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def update_metadata_uri(self, operator_address: str, uri: str) -> TxReceipt:
        func = self.delegation_manager.functions.updateOperatorMetadataURI(
            Web3.to_checksum_address(operator_address),
            uri,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def deposit_erc20_into_strategy(self, strategy_addr: str, amount: int) -> TxReceipt:
        _, token_contract, token_addr = (
            self.el_chain_reader.get_strategy_and_underlying_erc20_token(strategy_addr)
        )

        func = token_contract.functions.approve(
            self.strategy_manager.address,
            amount,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        func = self.strategy_manager.functions.depositIntoStrategy(
            Web3.to_checksum_address(strategy_addr),
            Web3.to_checksum_address(token_addr),
            amount,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def set_claimer_for(self, claimer: str) -> TxReceipt:
        func = self.rewards_coordinator.functions.setClaimerFor(
            Web3.to_checksum_address(claimer),
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def process_claim(self, claim: dict, recipient_address: str) -> TxReceipt:

        func = self.rewards_coordinator.functions.processClaim(
            claim,
            Web3.to_checksum_address(recipient_address),
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def set_operator_avs_split(self, operator: str, avs: str, split: int) -> TxReceipt:

        func = self.rewards_coordinator.functions.setOperatorAVSSplit(
            Web3.to_checksum_address(operator),
            Web3.to_checksum_address(avs),
            split,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def set_operator_pi_split(self, operator: str, split: int) -> TxReceipt:

        func = self.rewards_coordinator.functions.setOperatorPISplit(
            Web3.to_checksum_address(operator),
            split,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def modify_allocations(self, operator_address: str, allocations: list) -> TxReceipt:

        func = self.allocation_manager.functions.modifyAllocations(
            Web3.to_checksum_address(operator_address),
            allocations,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def clear_deallocation_queue(
        self, operator_address: str, strategies: list, nums_to_clear: list
    ) -> TxReceipt:

        func = self.allocation_manager.functions.clearDeallocationQueue(
            Web3.to_checksum_address(operator_address),
            [Web3.to_checksum_address(s) for s in strategies],
            nums_to_clear,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def set_allocation_delay(self, operator_address: str, delay: int) -> TxReceipt:

        func = self.allocation_manager.functions.setAllocationDelay(
            Web3.to_checksum_address(operator_address),
            delay,
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def deregister_from_operator_sets(self, operator: str, request: dict) -> TxReceipt:

        func = self.allocation_manager.functions.deregisterFromOperatorSets(
            {
                "operator": Web3.to_checksum_address(operator),
                "avs": Web3.to_checksum_address(request["avs_address"]),
                "operatorSetIds": request["operator_set_ids"],
            }
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def register_for_operator_sets(
        self, registry_coordinator_addr: str, request: dict
    ) -> TxReceipt:

        func = self.allocation_manager.functions.registerForOperatorSets(
            Web3.to_checksum_address(request["operator_address"]),
            {
                "avs": Web3.to_checksum_address(request["avs_address"]),
                "operatorSetIds": request["operator_set_ids"],
                "data": abi_encode_registration_params(
                    RegistrationType.NORMAL,
                    request["socket"],
                    get_pubkey_registration_params(
                        self.eth_http_client,
                        cast(Address, Web3.to_checksum_address(registry_coordinator_addr)),
                        cast(Address, Web3.to_checksum_address(request["operator_address"])),
                        request["bls_key_pair"],
                    ),
                ),
            },
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def remove_permission(self, request: dict) -> TxReceipt:

        func = self.permission_controller.functions.removeAppointee(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["appointee_address"]),
            request["target"],
            request["selector"],
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def set_permission(self, request: dict) -> TxReceipt:

        func = self.permission_controller.functions.removeAppointee(
            Web3.to_checksum_address(request["account_address"].lower()),
            Web3.to_checksum_address(request["appointee_address"].lower()),
            Web3.to_checksum_address(request["target"].lower()),
            request["selector"],
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def accept_admin(self, request: dict) -> TxReceipt:

        func = self.permission_controller.functions.acceptAdmin(
            Web3.to_checksum_address(request["account_address"]),
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def add_pending_admin(self, request: dict) -> TxReceipt:

        func = self.permission_controller.functions.addPendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def remove_admin(self, request: dict) -> TxReceipt:
        func = self.permission_controller.functions.removeAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def remove_pending_admin(self, request: dict) -> TxReceipt:

        func = self.permission_controller.functions.removePendingAdmin(
            Web3.to_checksum_address(request["account_address"]),
            Web3.to_checksum_address(request["admin_address"]),
        )

        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)

        return receipt

    def get_operator_id(self, operator_address: Address) -> bytes:
        operator_id = self.registry_coordinator.functions.getOperatorId(
            Web3.to_checksum_address(cast(Address, operator_address))
        ).call()
        return operator_id

    def get_operator_from_id(self, operator_id: bytes) -> Address:
        operator_address = self.registry_coordinator.functions.getOperatorFromId(operator_id).call()
        return cast(Address, Web3.to_checksum_address(operator_address))
