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
from typing import cast
from web3.types import TxParams


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
    def get_quorum_count(self, call_options: Optional[TxParams] = None) -> int:
        return int(self.registry_coordinator.functions.quorumCount().call(call_options))

    @typechecked
    def get_operators_stake_in_quorums_at_current_block(self, call_options: Optional[TxParams], quorum_numbers: List[int]) -> List[List[OperatorStateRetrieverOperator]]:
        return self.get_operators_stake_in_quorums_at_block(call_options, quorum_numbers, int(self.eth_client.eth.block_number))


    @typechecked
    def get_operators_stake_in_quorums_at_block(self, call_options: Optional[TxParams], quorum_numbers: List[int], block_number: int) -> List[List[OperatorStateRetrieverOperator]]:
        return self.operator_state_retriever.functions.getOperatorState(self.registry_coordinator_addr, quorum_numbers, block_number).call(call_options)


    @typechecked
    def get_operator_addrs_in_quorums_at_current_block(self, call_options: Optional[TxParams], quorum_numbers: List[int]) -> List[List[str]]:
        stakes = self.operator_state_retriever.functions.getOperatorState(self.registry_coordinator_addr, quorum_numbers, int(self.eth_client.eth.block_number)).call(call_options)
        return [[str(op["operator"]) for op in quorum] for quorum in stakes]


    @typechecked
    def get_operators_stake_in_quorums_of_operator_at_block(self, call_options: Optional[TxParams], operator_id: int, block_number: int) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        bitmap, stakes = self.operator_state_retriever.functions.getOperatorState0(self.registry_coordinator_addr, operator_id, block_number).call(call_options or {})
        return bitmap_to_quorum_ids(bitmap), cast(Optional[List[List[OperatorStateRetrieverOperator]]], stakes)

    @typechecked
    def get_operators_stake_in_quorums_of_operator_at_current_block(self, call_options: Optional[TxParams], operator_id: int) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        opts = dict(call_options or {})
        opts["block_number"] = self.eth_client.eth.block_number
        return self.get_operators_stake_in_quorums_of_operator_at_block(opts, operator_id, int(opts["block_number"]))


    @typechecked
    def get_operator_stake_in_quorums_of_operator_at_current_block(self, call_options: Optional[TxParams], operator_id: int) -> Optional[Dict[int, int]]:
        opts = dict(call_options or {})
        opts.setdefault("block_number", self.eth_client.eth.block_number) if "block_hash" not in opts else None

        quorums = bitmap_to_quorum_ids(self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(opts))
        return {q: int(self.stake_registry.functions.getCurrentStake(operator_id, q).call(opts)) for q in quorums}


    @typechecked
    def weight_of_operator_for_quorum(self, call_options: Optional[TxParams], quorum_number: int, operator_addr: str) -> Optional[int]:
        return int(self.stake_registry.functions.weightOfOperatorForQuorum(quorum_number, operator_addr).call(call_options or {}))


    @typechecked
    def strategy_params_length(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.strategyParamsLength(quorum_number).call(call_options or {}))


    @typechecked
    def strategy_params_by_index(self, call_options: Optional[TxParams], quorum_number: int, index: int) -> Optional[StakeRegistryTypesStrategyParams]:
        param = self.stake_registry.functions.strategyParamsByIndex(quorum_number, index).call(call_options or {})
        
        if isinstance(param, tuple):
            return StakeRegistryTypesStrategyParams(strategy=str(param[0]), multiplier=int(param[1]))
        
        if isinstance(param, dict):
            strategy = param.get("strategy") or param.get("Strategy")
            multiplier = param.get("multiplier") or param.get("Multiplier")
            if strategy is None or multiplier is None:
                return None
            return StakeRegistryTypesStrategyParams(strategy=str(strategy), multiplier=int(multiplier))
        
        return None


    @typechecked
    def get_stake_history_length(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.getStakeHistoryLength(operator_id, quorum_number).call(call_options or {}))


    @typechecked
    def get_stake_history(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int) -> Optional[List[StakeRegistryTypesStakeUpdate]]:
        raw_history = self.stake_registry.functions.getStakeHistory(operator_id, quorum_number).call(call_options or {})
        history = []

        for update in raw_history:
            if isinstance(update, tuple):
                history.append(StakeRegistryTypesStakeUpdate(
                    update_block_number=int(update[0]),
                    next_update_block_number=int(update[1]),
                    stake=int(update[2]),
                ))
            elif isinstance(update, dict):
                history.append(StakeRegistryTypesStakeUpdate(
                    update_block_number=int(update.get("updateBlockNumber") or update.get("UpdateBlockNumber") or 0),
                    next_update_block_number=int(update.get("nextUpdateBlockNumber") or update.get("NextUpdateBlockNumber") or 0),
                    stake=int(update.get("stake") or update.get("Stake") or 0),
                ))

        return history


    @typechecked
    def get_latest_stake_update(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int) -> Optional[StakeRegistryTypesStakeUpdate]:
        update = self.stake_registry.functions.getLatestStakeUpdate(operator_id, quorum_number).call(call_options or {})

        if isinstance(update, tuple):
            return StakeRegistryTypesStakeUpdate(
                update_block_number=int(update[0]),
                next_update_block_number=int(update[1]),
                stake=int(update[2])
            )
        
        if isinstance(update, dict):
            return StakeRegistryTypesStakeUpdate(
                update_block_number=int(update.get("updateBlockNumber") or update.get("UpdateBlockNumber") or 0),
                next_update_block_number=int(update.get("nextUpdateBlockNumber") or update.get("NextUpdateBlockNumber") or 0),
                stake=int(update.get("stake") or update.get("Stake") or 0)
            )

        return None


    @typechecked
    def get_stake_update_at_index(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int, index: int) -> Optional[StakeRegistryTypesStakeUpdate]:
        update = self.stake_registry.functions.getStakeUpdateAtIndex(quorum_number, operator_id, index).call(call_options or {})

        if isinstance(update, tuple):
            return StakeRegistryTypesStakeUpdate(
                update_block_number=int(update[0]),
                next_update_block_number=int(update[1]),
                stake=int(update[2])
            )
        
        if isinstance(update, dict):
            return StakeRegistryTypesStakeUpdate(
                update_block_number=int(update.get("updateBlockNumber") or update.get("UpdateBlockNumber") or 0),
                next_update_block_number=int(update.get("nextUpdateBlockNumber") or update.get("NextUpdateBlockNumber") or 0),
                stake=int(update.get("stake") or update.get("Stake") or 0)
            )

        return None


    @typechecked
    def get_stake_at_block_number(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int, block_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.getStakeAtBlockNumber(operator_id, quorum_number, block_number).call(call_options or {}))


    @typechecked
    def get_stake_update_index_at_block_number(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int, block_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(operator_id, quorum_number, block_number).call(call_options or {}))


    @typechecked
    def get_stake_at_block_number_and_index(self, call_options: Optional[TxParams], operator_id: int, quorum_number: int, block_number: int, index: int) -> Optional[int]:
        return int(self.stake_registry.functions.getStakeAtBlockNumberAndIndex(quorum_number, block_number, operator_id, index).call(call_options or {}))


    @typechecked
    def get_total_stake_history_length(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.getTotalStakeHistoryLength(quorum_number).call(call_options or {}))


    @typechecked
    def get_check_signatures_indices(self, call_options: Optional[TxParams], reference_block_number: int, quorum_numbers: List[int], non_signer_operator_ids: List[int]) -> OperatorStateRetrieverCheckSignaturesIndices:
        return self.operator_state_retriever.functions.getCheckSignaturesIndices(
            self.registry_coordinator_addr,
            reference_block_number,
            list(quorum_numbers),
            non_signer_operator_ids
        ).call(call_options or {})


    @typechecked
    def get_current_total_stake(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.getCurrentTotalStake(quorum_number).call(call_options or {}))


    @typechecked
    def get_total_stake_update_at_index(self, call_options: Optional[TxParams], quorum_number: int, index: int) -> Optional[StakeRegistryTypesStakeUpdate]:
        update = self.stake_registry.functions.getTotalStakeUpdateAtIndex(quorum_number, index).call(call_options or {})

        if isinstance(update, tuple):
            return StakeRegistryTypesStakeUpdate(int(update[0]), int(update[1]), int(update[2]))

        if isinstance(update, dict):
            return StakeRegistryTypesStakeUpdate(
                int(update.get("updateBlockNumber") or update.get("UpdateBlockNumber") or 0),
                int(update.get("nextUpdateBlockNumber") or update.get("NextUpdateBlockNumber") or 0),
                int(update.get("stake") or update.get("Stake") or 0)
            )

        return None


    @typechecked
    def get_total_stake_at_block_number_from_index(self, call_options: Optional[TxParams], quorum_number: int, block_number: int, index: int) -> Optional[int]:
        return int(self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(quorum_number, block_number, index).call(call_options or {}))


    @typechecked
    def get_total_stake_indices_at_block_number(self, call_options: Optional[TxParams], quorum_numbers: List[int], block_number: int) -> Optional[List[int]]:
        return list(map(int, self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(block_number, quorum_numbers).call(call_options or {})))


    @typechecked
    def get_minimum_stake_for_quorum(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.minimumStakeForQuorum(quorum_number).call(call_options or {}))


    @typechecked
    def get_strategy_params_at_index(self, call_options: Optional[TxParams], quorum_number: int, index: int) -> Optional[StakeRegistryTypesStrategyParams]:
        raw = self.stake_registry.functions.strategyParams(quorum_number, index).call(call_options or {})

        if isinstance(raw, tuple) and len(raw) >= 2:
            return StakeRegistryTypesStrategyParams(strategy=str(raw[0]), multiplier=int(raw[1]))

        if isinstance(raw, dict):
            strategy = raw.get("strategy") or raw.get("Strategy")
            multiplier = raw.get("multiplier") or raw.get("Multiplier")
            if strategy and multiplier:
                return StakeRegistryTypesStrategyParams(strategy=str(strategy), multiplier=int(multiplier))

        return None


    @typechecked
    def get_strategy_per_quorum_at_index(self, call_options: Optional[TxParams], quorum_number: int, index: int) -> Optional[str]:
        return str(self.stake_registry.functions.strategiesPerQuorum(quorum_number, index).call(call_options or {}))


    @typechecked
    def get_restakeable_strategies(self, call_options: Optional[TxParams]) -> List[str]:
        return remove_duplicate_strategies(list(map(str, self.service_manager.functions.getRestakeableStrategies().call(call_options or {}))))


    @typechecked
    def get_operator_restaked_strategies(self, call_options: Optional[TxParams], operator: str) -> List[str]:
        return remove_duplicate_strategies(list(map(str, self.service_manager.functions.getOperatorRestakedStrategies(operator).call(call_options or {}))))


    @typechecked
    def get_stake_type_per_quorum(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.stakeTypePerQuorum(quorum_number).call(call_options or {}))


    @typechecked
    def get_slashable_stake_look_ahead_per_quorum(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[int]:
        return int(self.stake_registry.functions.slashableStakeLookAheadPerQuorum(quorum_number).call(call_options or {}))


    @typechecked
    def get_operator_id(self, call_options: Optional[TxParams], operator_address: str) -> Optional[bytes]:
        return bytes(self.registry_coordinator.functions.getOperatorId(operator_address).call(call_options or {}))


    @typechecked
    def get_operator_from_id(self, call_options: Optional[TxParams], operator_id: int) -> Optional[str]:
        return str(self.registry_coordinator.functions.getOperatorFromId(operator_id).call(call_options or {}))


    @typechecked
    def query_registration_detail(self, call_options: Optional[TxParams], operator_address: str) -> Optional[List[bool]]:
        operator_id = self.get_operator_id(call_options or {}, operator_address)
        if operator_id is None:
            return None

        value = int(self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(call_options or {}))
        return [(value & (1 << i)) != 0 for i in range(value.bit_length())]


    @typechecked
    def is_operator_registered(self, call_options: Optional[TxParams], operator_address: str) -> bool:
        return int(self.registry_coordinator.functions.getOperatorStatus(operator_address).call(call_options or {})) == 1


    @typechecked
    def is_operator_set_quorum(self, call_options: Optional[TxParams], quorum_number: int) -> Optional[bool]:
        return bool(self.stake_registry.functions.isOperatorSetQuorum(quorum_number).call(call_options or {}))


    @typechecked
    def get_operator_id_from_operator_address(self, call_options: Optional[TxParams], operator_address: str) -> Optional[bytes]:
        return bytes(self.bls_apk_registry.functions.operatorToPubkeyHash(operator_address).call(call_options or {}))


    @typechecked
    def get_operator_address_from_operator_id(self, call_options: Optional[TxParams], operator_pubkey_hash: bytes) -> Optional[str]:
        return str(self.bls_apk_registry.functions.pubkeyHashToOperator(operator_pubkey_hash).call(call_options or {}))


    @typechecked
    def get_pubkey_from_operator_address(self, call_options: Optional[TxParams], operator_address: str) -> Optional[G1Point]:
        operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(operator_address).call(call_options or {})
        return G1Point(int(operator_pubkey["x"]), int(operator_pubkey["y"]))


    @typechecked
    def get_apk_update(self, call_options: Optional[TxParams], quorum_number: int, index: int) -> Optional[BLSApkRegistryTypesApkUpdate]:
        update = self.bls_apk_registry.functions.apkHistory(quorum_number, index).call(call_options or {})
        return BLSApkRegistryTypesApkUpdate(
            apk_hash=bytes(update["apkHash"]),
            update_block_number=int(update["updateBlockNumber"]),
            next_update_block_number=int(update["nextUpdateBlockNumber"]),
        )


    @typechecked
    def get_current_apk(self, call_options: Optional[dict], quorum_number: int) -> Optional[G1Point]:
        apk = self.bls_apk_registry.functions.currentApk(quorum_number).call(call_options or {})
        return G1Point(int(apk["x"]), int(apk["y"]))


    @typechecked
    def query_existing_registered_operator_sockets(self, start_block: Optional[int], stop_block: Optional[int], block_range: Optional[int]) -> Optional[Dict[bytes, str]]:
        start_block = start_block or 0
        stop_block = stop_block or self.eth_client.eth.block_number
        block_range = block_range or DEFAULT_QUERY_BLOCK_RANGE

        operator_id_to_socket_map = {}
        for i in range(start_block, stop_block + 1, block_range):
            to_block = min(i + block_range - 1, stop_block)
            filter_opts = {"fromBlock": i, "toBlock": to_block}

            socket_updates = self.registry_coordinator.events.OperatorSocketUpdate().get_logs(filter_opts)
            num_socket_updates = 0
            for event in socket_updates:
                args = event["args"]
                operator_id_raw = args.get("operatorId")

                operator_id = (
                    operator_id_raw if isinstance(operator_id_raw, bytes)
                    else bytes.fromhex(operator_id_raw[2:] if operator_id_raw.startswith("0x") else operator_id_raw)
                    if isinstance(operator_id_raw, str)
                    else None
                )

                if operator_id is None:
                    continue  # Skip invalid type

                operator_id_to_socket_map[operator_id] = str(args.get("socket", ""))
                num_socket_updates += 1

            self.logger.debug(
                "avs_registry_chain_reader.query_existing_registered_operator_sockets",
                extra={"numTransactionLogs": num_socket_updates, "fromBlock": i, "toBlock": to_block}
            )

        return operator_id_to_socket_map