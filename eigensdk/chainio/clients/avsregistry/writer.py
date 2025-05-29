import logging
from typing import List, Optional, Dict, Any, Tuple

from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from web3.types import TxReceipt

from eigensdk.chainio import utils
from ..elcontracts.reader import ELReader
from ...utils import send_transaction


class AvsRegistryWriter:
    def __init__(
        self,
        registry_coordinator: Contract,
        operator_state_retriever: Contract,
        service_manager: Contract,
        service_manager_addr: Address,
        stake_registry: Contract,
        bls_apk_registry: Contract,
        el_reader: ELReader,
        logger: logging.Logger,
        eth_http_client: Web3,
        pk_wallet: LocalAccount,
        service_manager_abi: Optional[List[Dict[str, Any]]] = None,
    ):

        self.registry_coordinator: Contract = registry_coordinator
        self.operator_state_retriever: Contract = operator_state_retriever
        self.service_manager: Contract = service_manager
        self.service_manager_addr: Address = service_manager_addr
        self.stake_registry: Contract = stake_registry
        self.bls_apk_registry: Contract = bls_apk_registry
        self.el_reader: ELReader = el_reader
        self.logger: logging.Logger = logger
        self.eth_http_client: Web3 = eth_http_client
        self.web3: Web3 = eth_http_client  # Create alias for compatibility
        self.service_manager_abi: Optional[List[Dict[str, Any]]] = service_manager_abi
        self.pk_wallet: LocalAccount = pk_wallet

        if registry_coordinator is None:
            self.logger.warning("RegistryCoordinator contract not provided")

        if operator_state_retriever is None:
            self.logger.warning("OperatorStateRetriever contract not provided")

        if service_manager is None:
            self.logger.warning("ServiceManager contract not provided")

        if service_manager_addr is None:
            self.logger.warning("ServiceManager address not provided")

        if stake_registry is None:
            self.logger.warning("StakeRegistry contract not provided")

        if eth_http_client is None:
            self.logger.warning("EthHTTPClient not provided")

        if pk_wallet is None:
            self.logger.warning("PKWallet not provided")

        if service_manager_abi is None:
            self.logger.warning("ServiceManager ABI not provided")

    def update_stakes_of_entire_operator_set_for_quorums(
        self,
        operators_per_quorum: List[List[str]],
        quorum_numbers: List[int],
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.updateOperatorsForQuorum(
            operators_per_quorum,
            utils.nums_to_bytes(quorum_numbers),
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def update_stakes_of_operator_subset_for_all_quorums(self, operators: List[str]) -> TxReceipt:
        func = self.registry_coordinator.functions.updateOperators(operators)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def update_socket(
        self,
        socket: str,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.updateSocket(socket)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_rewards_initiator(
        self,
        rewards_initiator_addr: str,
    ) -> TxReceipt:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )
        func = service_manager_contract.functions.setRewardsInitiator(rewards_initiator_addr)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_slashable_stake_lookahead(
        self,
        quorum_number: int,
        look_ahead_period: int,
    ) -> TxReceipt:
        func = self.stake_registry.functions.setSlashableStakeLookahead(
            quorum_number, look_ahead_period
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_minimum_stake_for_quorum(
        self,
        quorum_number: int,
        minimum_stake: int,
    ) -> TxReceipt:
        func = self.stake_registry.functions.setMinimumStakeForQuorum(quorum_number, minimum_stake)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def create_total_delegated_stake_quorum(
        self,
        operator_set_params: Tuple[int, int, int],
        minimum_stake_required: int,
        strategy_params: List[Tuple[str, int]],
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.createTotalDelegatedStakeQuorum(
            operator_set_params, minimum_stake_required, strategy_params
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def create_slashable_stake_quorum(
        self,
        operator_set_params: Tuple[int, int, int],
        minimum_stake_required: int,
        strategy_params: List[Tuple[str, int]],
        look_ahead_period: int,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.createSlashableStakeQuorum(
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            look_ahead_period,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def eject_operator(
        self,
        operator_address: str,
        quorum_numbers: List[int],
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.ejectOperator(
            operator_address,
            utils.nums_to_bytes(quorum_numbers),
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_operator_set_params(
        self,
        quorum_number: int,
        operator_set_params: Dict,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.setOperatorSetParams(
            quorum_number,
            operator_set_params,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_churn_approver(
        self,
        churn_approver_address: str,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.setChurnApprover(churn_approver_address)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_ejector(
        self,
        ejector_address: str,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.setEjector(ejector_address)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def modify_strategy_params(
        self,
        quorum_number: int,
        strategy_indices: List[int],
        multipliers: List[int],
    ) -> TxReceipt:
        func = self.stake_registry.functions.modifyStrategyParams(
            quorum_number,
            strategy_indices,
            multipliers,
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_avs(self, avs_address: str) -> TxReceipt:
        func = self.registry_coordinator.functions.setAVS(avs_address)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def set_ejection_cooldown(
        self,
        ejection_cooldown: int,
    ) -> TxReceipt:
        func = self.registry_coordinator.functions.setEjectionCooldown(ejection_cooldown)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def add_strategies(
        self,
        quorum_number: int,
        strategy_params: List[Dict],
    ) -> TxReceipt:
        func = self.stake_registry.functions.addStrategies(quorum_number, strategy_params)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client, gas_limit=20000000)
        return receipt

    def update_avs_metadata_uri(
        self,
        metadata_uri: str,
    ) -> TxReceipt:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )
        func = service_manager_contract.functions.updateAVSMetadataURI(metadata_uri)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def remove_strategies(
        self,
        quorum_number: int,
        indices_to_remove: List[int],
    ) -> TxReceipt:
        func = self.stake_registry.functions.removeStrategies(quorum_number, indices_to_remove)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def create_avs_rewards_submission(
        self,
        rewards_submission: List[Dict],
    ) -> TxReceipt:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )
        func = service_manager_contract.functions.createAVSRewardsSubmission(rewards_submission)
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def create_operator_directed_avs_rewards_submission(
        self,
        operator_directed_rewards_submissions: List[Dict],
    ) -> TxReceipt:
        service_manager_contract = self.web3.eth.contract(
            address=self.service_manager_addr, abi=self.service_manager_abi
        )
        func = service_manager_contract.functions.createOperatorDirectedAVSRewardsSubmission(
            operator_directed_rewards_submissions
        )
        receipt = send_transaction(func, self.pk_wallet, self.eth_http_client)
        return receipt

    def is_registry_coordinator_owner(self, address: str) -> bool:
        owner_address = self.registry_coordinator.functions.owner().call()
        return owner_address.lower() == address.lower()
