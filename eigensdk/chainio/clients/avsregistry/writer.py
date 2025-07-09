import logging
from typing import List, Dict, Tuple

from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract, ContractFunction
from web3.types import TxReceipt

from eigensdk.chainio.utils import Transactor, nums_to_bytes
from eigensdk.chainio.clients.elcontracts.reader import ELReader


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
    ):
        """Initialize the AvsRegistryWriter with contract instances and configuration."""
        self.registry_coordinator: Contract = registry_coordinator
        self.operator_state_retriever: Contract = operator_state_retriever
        self.service_manager: Contract = service_manager
        self.service_manager_addr: Address = service_manager_addr
        self.stake_registry: Contract = stake_registry
        self.bls_apk_registry: Contract = bls_apk_registry
        self.el_reader: ELReader = el_reader
        self.logger: logging.Logger = logger
        self.web3: Web3 = eth_http_client  # Create alias for compatibility
        self.transactor = Transactor(pk_wallet, eth_http_client)

    def send_transaction(self, func: ContractFunction):
        """Send a transaction using the configured transactor."""
        return self.transactor.send(func)

    def update_stakes_of_entire_operator_set_for_quorums(
        self,
        operators_per_quorum: List[List[str]],
        quorum_numbers: List[int],
    ) -> TxReceipt:
        """
        Used by avs teams running https://github.com/Layr-Labs/avs-sync to update the stake of
        their entire operator set. Due to high gas costs, typically needs to be called per quorum.
        """
        func = self.registry_coordinator.functions.updateOperatorsForQuorum(
            operators_per_quorum,
            nums_to_bytes(quorum_numbers),
        )
        return self.send_transaction(func)

    def update_stakes_of_operator_subset_for_all_quorums(self, operators: List[str]) -> TxReceipt:
        """Updates the stakes of the given operators for all the quorums."""
        func = self.registry_coordinator.functions.updateOperators(operators)
        return self.send_transaction(func)

    def update_socket(
        self,
        socket: str,
    ) -> TxReceipt:
        """Updates the socket of the sender (if it is a registered operator)."""
        func = self.registry_coordinator.functions.updateSocket(socket)
        return self.send_transaction(func)

    def set_rewards_initiator(
        self,
        rewards_initiator_addr: str,
    ) -> TxReceipt:
        """Sets the rewards initiator address.

        This is the only address allowed to initiate rewards.
        """
        func = self.service_manager.functions.setRewardsInitiator(rewards_initiator_addr)
        return self.send_transaction(func)

    def set_slashable_stake_lookahead(
        self,
        quorum_number: int,
        look_ahead_period: int,
    ) -> TxReceipt:
        """Sets the look ahead time for checking operator shares for a specific quorum."""
        func = self.stake_registry.functions.setSlashableStakeLookahead(
            quorum_number, look_ahead_period
        )
        return self.send_transaction(func)

    def set_minimum_stake_for_quorum(
        self,
        quorum_number: int,
        minimum_stake: int,
    ) -> TxReceipt:
        """Sets the minimum stake required for a specific quorum."""
        func = self.stake_registry.functions.setMinimumStakeForQuorum(quorum_number, minimum_stake)
        return self.send_transaction(func)

    def create_total_delegated_stake_quorum(
        self,
        operator_set_params: Tuple[int, int, int],
        minimum_stake_required: int,
        strategy_params: List[Tuple[str, int]],
    ) -> TxReceipt:
        """Creates a new quorum tracking total delegated stake.

        Requires quorum params and minimum stake.
        """
        func = self.registry_coordinator.functions.createTotalDelegatedStakeQuorum(
            operator_set_params, minimum_stake_required, strategy_params
        )
        return self.send_transaction(func)

    def create_slashable_stake_quorum(
        self,
        operator_set_params: Tuple[int, int, int],
        minimum_stake_required: int,
        strategy_params: List[Tuple[str, int]],
        look_ahead_period: int,
    ) -> TxReceipt:
        """Creates a quorum tracking slashable stake.

        Includes minimum stake and look ahead period. Only works on M2 AVSs.
        """
        func = self.registry_coordinator.functions.createSlashableStakeQuorum(
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            look_ahead_period,
        )
        return self.send_transaction(func)

    def eject_operator(
        self,
        operator_address: str,
        quorum_numbers: List[int],
    ) -> TxReceipt:
        """Ejects an operator from the specified quorums.

        Does nothing if the operator is not registered.
        """
        func = self.registry_coordinator.functions.ejectOperator(
            operator_address,
            nums_to_bytes(quorum_numbers),
        )
        return self.send_transaction(func)

    def set_operator_set_params(
        self,
        quorum_number: int,
        operator_set_params: Dict,
    ) -> TxReceipt:
        """Sets max operator count and churn parameters for a specific quorum."""
        func = self.registry_coordinator.functions.setOperatorSetParams(
            quorum_number,
            operator_set_params,
        )
        return self.send_transaction(func)

    def set_churn_approver(
        self,
        churn_approver_address: str,
    ) -> TxReceipt:
        """Sets the churnApprover address, whose signature is required in churn registration."""
        func = self.registry_coordinator.functions.setChurnApprover(churn_approver_address)
        return self.send_transaction(func)

    def set_ejector(
        self,
        ejector_address: str,
    ) -> TxReceipt:
        """Sets the ejector address.

        This is the only address allowed to eject operators.
        """
        func = self.registry_coordinator.functions.setEjector(ejector_address)
        return self.send_transaction(func)

    def modify_strategy_params(
        self,
        quorum_number: int,
        strategy_indices: List[int],
        multipliers: List[int],
    ) -> TxReceipt:
        """Modifies multipliers for existing strategies in a specific quorum."""
        func = self.stake_registry.functions.modifyStrategyParams(
            quorum_number,
            strategy_indices,
            multipliers,
        )
        return self.send_transaction(func)

    def set_avs(self, avs_address: str) -> TxReceipt:
        """Sets the AVS address (identifier).

        Should only be set once.
        """
        func = self.registry_coordinator.functions.setAVS(avs_address)
        return self.send_transaction(func)

    def set_ejection_cooldown(
        self,
        ejection_cooldown: int,
    ) -> TxReceipt:
        """Sets the ejection cooldown: the waiting time before an ejected operator can rejoin."""
        func = self.registry_coordinator.functions.setEjectionCooldown(ejection_cooldown)
        return self.send_transaction(func)

    def add_strategies(
        self,
        quorum_number: int,
        strategy_params: List[Dict],
    ) -> TxReceipt:
        """Adds new strategies and multipliers to the specified quorum."""
        func = self.stake_registry.functions.addStrategies(quorum_number, strategy_params)
        return self.send_transaction(func)

    def update_avs_metadata_uri(
        self,
        metadata_uri: str,
    ) -> TxReceipt:
        """Updates the metadata URI for the AVS."""
        func = self.service_manager.functions.updateAVSMetadataURI(metadata_uri)
        return self.send_transaction(func)

    def remove_strategies(
        self,
        quorum_number: int,
        indices_to_remove: List[int],
    ) -> TxReceipt:
        """Removes strategies and their weights from the specified quorum."""
        func = self.stake_registry.functions.removeStrategies(quorum_number, indices_to_remove)
        return self.send_transaction(func)

    def create_avs_rewards_submission(
        self,
        rewards_submission: List[Dict],
    ) -> TxReceipt:
        """Creates a new AVS rewards submission for registered operators' stakers.

        Includes various validations and possible failure conditions.
        """
        func = self.service_manager.functions.createAVSRewardsSubmission(rewards_submission)
        return self.send_transaction(func)

    def create_operator_directed_avs_rewards_submission(
        self,
        operator_directed_rewards_submissions: List[Dict],
    ) -> TxReceipt:
        """Creates operator-directed AVS rewards submission.

        Multiple validations apply (e.g., address order, signature permissions).
        """
        func = self.service_manager.functions.createOperatorDirectedAVSRewardsSubmission(
            operator_directed_rewards_submissions
        )
        return self.send_transaction(func)
