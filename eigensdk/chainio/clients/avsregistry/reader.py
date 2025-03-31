import logging
import math
from typing import Dict, List, Optional, Tuple, Any
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from eigensdk._types import (
    OperatorPubkeys,
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
)
from eigensdk.chainio import utils
from eigensdk.chainio.chainio_utils.utils import *
from eigensdk.crypto.bls.attestation import G1Point, G2Point
from eigensdk._types import (
    StakeRegistryTypesStrategyParams,
    StakeRegistryTypesStakeUpdate,
    BLSApkRegistryTypesApkUpdate,
)

from typeguard import typechecked

DEFAULT_QUERY_BLOCK_RANGE = 10_000


class AvsRegistryReader:
    def __init__(
        self,
        registry_coordinator: Contract,
        registry_coordinator_addr: Address,
        bls_apk_registry: Contract,
        bls_apk_registry_addr: Address,
        operator_state_retriever: Contract,
        service_manager: Contract,
        stake_registry: Contract,
        logger: logging.Logger,
        eth_client: Web3,
        tx_mgr: Any,
    ):

        self.logger: logging.Logger = logger
        self.bls_apk_registry: Contract = bls_apk_registry
        self.bls_apk_registry_addr = bls_apk_registry_addr
        self.registry_coordinator: Contract = registry_coordinator
        self.registry_coordinator_addr = registry_coordinator_addr
        self.operator_state_retriever: Contract = operator_state_retriever
        self.service_manager = service_manager
        self.stake_registry: Contract = stake_registry
        self.eth_client: Web3 = eth_client
        self.tx_mgr = tx_mgr

        if registry_coordinator is None:
            raise ValueError("RegistryCoordinator contract not provided")

        if bls_apk_registry is None:
            raise ValueError("BLSApkRegistry contract not provided")

        if operator_state_retriever is None:
            raise ValueError("OperatorStateRetriever contract not provided")

        if service_manager is None:
            raise ValueError("ServiceManager contract not provided")

        if stake_registry is None:
            raise ValueError("StakeRegistry contract not provided")

    @typechecked
    def get_quorum_count(self, call_options: Optional[dict] = None) -> int:

        return self.registry_coordinator.functions.quorumCount().call(call_options)

    @typechecked
    def get_operators_stake_in_quorums_at_current_block(
        self, call_options: Optional[dict], quorum_numbers: List[int]
    ) -> List[List[OperatorStateRetrieverOperator]]:

        if (cur_block := self.eth_client.eth.block_number) > (2**32 - 1):
            raise ValueError("Current block number is too large to be converted to uint32")

        return self.get_operators_stake_in_quorums_at_block(
            call_options, quorum_numbers, int(cur_block)
        )

    @typechecked
    def get_operators_stake_in_quorums_at_block(
        self, call_options: Optional[dict], quorum_numbers: List[int], block_number: int
    ) -> Optional[List[List[OperatorStateRetrieverOperator]]]:

        return self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr,
            quorum_numbers,
            block_number,
        ).call(call_options)

    @typechecked
    def get_operator_addrs_in_quorums_at_current_block(
        self, call_options: Optional[dict], quorum_numbers: List[int]
    ) -> Optional[List[List[str]]]:

        cur_block = self.eth_client.eth.block_number
        if cur_block > (2**32 - 1):
            return None, ValueError("Current block number is too large to be converted to uint32")

        operator_stakes = self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr,
            quorum_numbers,
            int(cur_block),
        ).call(call_options)

        quorum_operator_addrs = [
            [operator["operator"] for operator in quorum] for quorum in operator_stakes
        ]

        return quorum_operator_addrs

    @typechecked
    def get_operators_stake_in_quorums_of_operator_at_block(
        self, call_options: Optional[dict], operator_id: int, block_number: int
    ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:

        quorum_bitmap, operator_stakes = self.operator_state_retriever.functions.getOperatorState0(
            self.registry_coordinator_addr, operator_id, block_number
        ).call(call_options)

        quorums = bitmap_to_quorum_ids(quorum_bitmap)

        return quorums, operator_stakes

    @typechecked
    def get_operators_stake_in_quorums_of_operator_at_current_block(
        self, call_options: Optional[dict], operator_id: int
    ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:

        if (cur_block := self.eth_client.eth.block_number) > (2**32 - 1):
            return (
                None,
                None,
                ValueError("Current block number is too large to be converted to uint32"),
            )

        call_options["block_number"] = cur_block

        return self.get_operators_stake_in_quorums_of_operator_at_block(
            call_options, operator_id, int(cur_block)
        )

    @typechecked
    def get_operator_stake_in_quorums_of_operator_at_current_block(
        self, call_options: Optional[dict], operator_id: int
    ) -> Optional[Dict[int, int]]:

        if "block_number" not in call_options and "block_hash" not in call_options:
            latest_block = self.eth_client.eth.block_number
            call_options["block_number"] = latest_block

        quorum_bitmap = self.registry_coordinator.functions.getCurrentQuorumBitmap(
            operator_id
        ).call(call_options)

        quorums = bitmap_to_quorum_ids(quorum_bitmap)
        quorum_stakes = {}

        for quorum in quorums:
            stake = self.stake_registry.functions.getCurrentStake(operator_id, int(quorum)).call(
                call_options
            )

            quorum_stakes[quorum] = stake

        return quorum_stakes

    @typechecked
    def weight_of_operator_for_quorum(
        self, call_options: Optional[dict], quorum_number: int, operator_addr: str
    ) -> Optional[int]:

        return self.stake_registry.functions.weightOfOperatorForQuorum(
            quorum_number, operator_addr
        ).call(call_options)

    @typechecked
    def strategy_params_length(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.strategyParamsLength(quorum_number).call(call_options)

    @typechecked
    def strategy_params_by_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:

        param = self.stake_registry.functions.strategyParamsByIndex(quorum_number, index).call(
            call_options
        )

        if isinstance(param, tuple):
            strategy_params = StakeRegistryTypesStrategyParams(
                strategy=param[0], multiplier=param[1]
            )
        else:
            strategy_params = StakeRegistryTypesStrategyParams(
                strategy=param.get("strategy") or param.get("Strategy"),
                multiplier=param.get("multiplier") or param.get("Multiplier"),
            )

        return strategy_params

    @typechecked
    def get_stake_history_length(
        self, call_options: Optional[dict], operator_id: int, quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.getStakeHistoryLength(operator_id, quorum_number).call(
            call_options
        )

    @typechecked
    def get_stake_history(
        self, call_options: Optional[dict], operator_id: int, quorum_number: int
    ) -> Optional[List[StakeRegistryTypesStakeUpdate]]:

        stake_history_raw = self.stake_registry.functions.getStakeHistory(
            operator_id, quorum_number
        ).call(call_options)

        stake_history = []
        for update in stake_history_raw:
            if isinstance(update, tuple):
                stake_update = StakeRegistryTypesStakeUpdate(
                    update_block_number=update[0],
                    next_update_block_number=update[1],
                    stake=update[2],
                )
            else:
                update_block = update.get("updateBlockNumber") or update.get("UpdateBlockNumber")
                next_update_block = update.get("nextUpdateBlockNumber") or update.get(
                    "NextUpdateBlockNumber"
                )
                stake = update.get("stake") or update.get("Stake")

                stake_update = StakeRegistryTypesStakeUpdate(
                    update_block_number=update_block,
                    next_update_block_number=next_update_block,
                    stake=stake,
                )

            stake_history.append(stake_update)

        return stake_history

    @typechecked
    def get_latest_stake_update(
        self, call_options: Optional[dict], operator_id: int, quorum_number: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:

        raw_stake_update = self.stake_registry.functions.getLatestStakeUpdate(
            operator_id, quorum_number
        ).call(call_options)

        if isinstance(raw_stake_update, tuple):
            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=raw_stake_update[0],
                next_update_block_number=raw_stake_update[1],
                stake=raw_stake_update[2],
            )
        else:
            update_block = raw_stake_update.get("updateBlockNumber")
            if update_block is None:
                update_block = raw_stake_update.get("UpdateBlockNumber", 0)

            next_update_block = raw_stake_update.get("nextUpdateBlockNumber")
            if next_update_block is None:
                next_update_block = raw_stake_update.get("NextUpdateBlockNumber", 0)

            stake = raw_stake_update.get("stake")
            if stake is None:
                stake = raw_stake_update.get("Stake", 0)

            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=update_block,
                next_update_block_number=next_update_block,
                stake=stake,
            )

        return stake_update

    @typechecked
    def get_stake_update_at_index(
        self,
        call_options: Optional[dict],
        operator_id: int,
        quorum_number: int,
        index: int,
    ) -> Optional[StakeRegistryTypesStakeUpdate]:

        raw_stake_update = self.stake_registry.functions.getStakeUpdateAtIndex(
            quorum_number, operator_id, index
        ).call(call_options)

        if isinstance(raw_stake_update, tuple):
            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=raw_stake_update[0],
                next_update_block_number=raw_stake_update[1],
                stake=raw_stake_update[2],
            )
        else:
            update_block = raw_stake_update.get("updateBlockNumber")
            if update_block is None:
                update_block = raw_stake_update.get("UpdateBlockNumber", 0)

            next_update_block = raw_stake_update.get("nextUpdateBlockNumber")
            if next_update_block is None:
                next_update_block = raw_stake_update.get("NextUpdateBlockNumber", 0)

            stake = raw_stake_update.get("stake")
            if stake is None:
                stake = raw_stake_update.get("Stake", 0)

            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=update_block,
                next_update_block_number=next_update_block,
                stake=stake,
            )

        return stake_update

    @typechecked
    def get_stake_at_block_number(
        self,
        call_options: Optional[dict],
        operator_id: int,
        quorum_number: int,
        block_number: int,
    ) -> Optional[int]:

        return self.stake_registry.functions.getStakeAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call(call_options)

    @typechecked
    def get_stake_update_index_at_block_number(
        self,
        call_options: Optional[dict],
        operator_id: int,
        quorum_number: int,
        block_number: int,
    ) -> Optional[int]:

        return self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call(call_options)

    @typechecked
    def get_stake_at_block_number_and_index(
        self,
        call_options: Optional[dict],
        operator_id: int,
        quorum_number: int,
        block_number: int,
        index: int,
    ) -> Optional[int]:

        return self.stake_registry.functions.getStakeAtBlockNumberAndIndex(
            quorum_number, block_number, operator_id, index
        ).call(call_options)

    @typechecked
    def get_total_stake_history_length(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.getTotalStakeHistoryLength(quorum_number).call(
            call_options
        )

    @typechecked
    def get_check_signatures_indices(
        self,
        call_options: Optional[dict],
        reference_block_number: int,
        quorum_numbers: List[int],
        non_signer_operator_ids: List[int],
    ) -> Optional[OperatorStateRetrieverCheckSignaturesIndices]:

        return self.operator_state_retriever.functions.getCheckSignaturesIndices(
            self.registry_coordinator_addr,
            reference_block_number,
            quorum_numbers.underlying_type(),
            non_signer_operator_ids,
        ).call(call_options)

    @typechecked
    def get_current_total_stake(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.getCurrentTotalStake(quorum_number).call(call_options)

    @typechecked
    def get_total_stake_update_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:

        raw_stake_update = self.stake_registry.functions.getTotalStakeUpdateAtIndex(
            quorum_number, index
        ).call(call_options)

        if isinstance(raw_stake_update, tuple):
            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=raw_stake_update[0],
                next_update_block_number=raw_stake_update[1],
                stake=raw_stake_update[2],
            )
        else:
            update_block = raw_stake_update.get("updateBlockNumber")
            if update_block is None:
                update_block = raw_stake_update.get("UpdateBlockNumber", 0)

            next_update_block = raw_stake_update.get("nextUpdateBlockNumber")
            if next_update_block is None:
                next_update_block = raw_stake_update.get("NextUpdateBlockNumber", 0)

            stake = raw_stake_update.get("stake")
            if stake is None:
                stake = raw_stake_update.get("Stake", 0)

            stake_update = StakeRegistryTypesStakeUpdate(
                update_block_number=update_block,
                next_update_block_number=next_update_block,
                stake=stake,
            )

        return stake_update

    @typechecked
    def get_total_stake_at_block_number_from_index(
        self,
        call_options: Optional[dict],
        quorum_number: int,
        block_number: int,
        index: int,
    ) -> Optional[int]:

        return self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(
            quorum_number, block_number, index
        ).call(call_options)

    @typechecked
    def get_total_stake_indices_at_block_number(
        self, call_options: Optional[dict], quorum_numbers: List[int], block_number: int
    ) -> Optional[List[int]]:

        return self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(
            block_number, quorum_numbers.underlying_type()
        ).call(call_options)

    @typechecked
    def get_minimum_stake_for_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.minimumStakeForQuorum(quorum_number).call(call_options)

    @typechecked
    def get_strategy_params_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:

        return self.stake_registry.functions.strategyParams(quorum_number, index).call(call_options)

    @typechecked
    def get_strategy_per_quorum_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[str]]:

        return self.stake_registry.functions.strategiesPerQuorum(quorum_number, index).call(
            call_options
        )

    @typechecked
    def get_restakeable_strategies(self, call_options: Optional[dict]) -> Optional[List[str]]:

        return remove_duplicate_strategies(
            self.service_manager.functions.getRestakeableStrategies().call(call_options)
        )

    @typechecked
    def get_operator_restaked_strategies(
        self, call_options: Optional[dict], operator: str
    ) -> Optional[List[str]]:

        return remove_duplicate_strategies(
            self.service_manager.functions.getOperatorRestakedStrategies(operator).call(
                call_options
            )
        )

    @typechecked
    def get_stake_type_per_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.stakeTypePerQuorum(quorum_number).call(call_options)

    @typechecked
    def get_slashable_stake_look_ahead_per_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[int]:

        return self.stake_registry.functions.slashableStakeLookAheadPerQuorum(quorum_number).call(
            call_options
        )

    @typechecked
    def get_operator_id(
        self, call_options: Optional[dict], operator_address: str
    ) -> Optional[bytes]:

        return self.registry_coordinator.functions.getint(operator_address).call(call_options)

    @typechecked
    def get_operator_from_id(self, call_options: Optional[dict], operator_id: int) -> Optional[str]:

        return self.registry_coordinator.functions.getOperatorFromId(operator_id).call(call_options)

    @typechecked
    def query_registration_detail(
        self, call_options: Optional[dict], operator_address: str
    ) -> Optional[List[bool]]:

        operator_id = self.get_operator_id(call_options, operator_address)

        value = self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(
            call_options
        )

        num_bits = value.bit_length()
        quorums = [(value & (1 << i)) != 0 for i in range(num_bits)]

        return quorums

    @typechecked
    def is_operator_registered(
        self, call_options: Optional[dict], operator_address: str
    ) -> Optional[bool]:

        registered_with_avs = (
            self.registry_coordinator.functions.getOperatorStatus(operator_address).call(
                call_options
            )
            == 1
        )

        return registered_with_avs

    @typechecked
    def is_operator_set_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[bool]:

        return self.stake_registry.functions.isOperatorSetQuorum(quorum_number).call(call_options)

    @typechecked
    def get_operator_id_from_operator_address(
        self, call_options: Optional[dict], operator_address: str
    ) -> Optional[bytes]:

        return self.bls_apk_registry.functions.operatorToPubkeyHash(operator_address).call(
            call_options
        )

    @typechecked
    def get_operator_address_from_operator_id(
        self, call_options: Optional[dict], operator_pubkey_hash: bytes
    ) -> Optional[str]:

        return self.bls_apk_registry.functions.pubkeyHashToOperator(operator_pubkey_hash).call(
            call_options
        )

    @typechecked
    def get_pubkey_from_operator_address(
        self, call_options: Optional[dict], operator_address: str
    ) -> Optional[G1Point]:

        operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(operator_address).call(
            call_options
        )

        operator_pubkey_g1 = G1Point(operator_pubkey["x"], operator_pubkey["y"])

        return operator_pubkey_g1

    @typechecked
    def get_apk_update(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Optional[BLSApkRegistryTypesApkUpdate]:

        update = self.bls_apk_registry.functions.apkHistory(quorum_number, index).call(call_options)

        apk_update = BLSApkRegistryTypesApkUpdate(
            apk_hash=update["apkHash"],
            update_block_number=update["updateBlockNumber"],
            next_update_block_number=update["nextUpdateBlockNumber"],
        )

        return apk_update

    @typechecked
    def get_current_apk(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Optional[G1Point]:

        apk = self.bls_apk_registry.functions.currentApk(quorum_number).call(call_options)

        apk_g1 = G1Point(apk["x"], apk["y"])

        return apk_g1

    @typechecked
    def query_existing_registered_operator_sockets(
        self,
        start_block: Optional[int],
        stop_block: Optional[int],
        block_range: Optional[int],
    ) -> Optional[Dict[bytes, str]]:

        if start_block is None:
            start_block = 0
        if stop_block is None:
            stop_block = self.eth_client.eth.block_number
        if block_range is None:
            block_range = DEFAULT_QUERY_BLOCK_RANGE

        operator_id_to_socket_map = {}  # Dict[bytes, str]

        i = start_block
        while i <= stop_block:
            to_block = min(i + block_range - 1, stop_block)

            filter_opts = {"fromBlock": i, "toBlock": to_block}

            socket_updates = self.registry_coordinator.events.OperatorSocketUpdate().get_logs(
                filter_opts
            )

            num_socket_updates = 0
            for event in socket_updates:
                # Get operator_id as bytes (Bytes32) instead of int
                operator_id = event["args"][
                    "operatorId"
                ]  # Assuming the correct field name is "operatorId"

                # Ensure operator_id is bytes
                if not isinstance(operator_id, bytes):
                    # Convert to bytes if it's not already bytes
                    # This depends on how the data is actually returned from the contract
                    operator_id = bytes.fromhex(
                        operator_id[2:] if operator_id.startswith("0x") else operator_id
                    )

                # Get socket as string
                socket = event["args"]["socket"]

                # Store in map
                operator_id_to_socket_map[operator_id] = socket
                num_socket_updates += 1

            self.logger.debug(
                "avs_registry_chain_reader.query_existing_registered_operator_sockets",
                extra={
                    "numTransactionLogs": num_socket_updates,
                    "fromBlock": i,
                    "toBlock": to_block,
                },
            )

            i += block_range

        return operator_id_to_socket_map
