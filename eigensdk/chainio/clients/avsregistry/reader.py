import logging
import math
from typing import Dict, List, Optional, Tuple, Any
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from eigensdk._types import (
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

    def get_quorum_count(self, call_options: Optional[TxParams] = None) -> int:
        return self.registry_coordinator.functions.quorumCount().call(call_options)

    def get_operators_stake_in_quorums_at_current_block(
        self, call_options: Optional[TxParams], quorum_numbers: List[int]
    ) -> List[List[OperatorStateRetrieverOperator]]:
        return self.get_operators_stake_in_quorums_at_block(
            call_options, quorum_numbers, int(self.eth_client.eth.block_number)
        )

    def get_operators_stake_in_quorums_at_block(
        self, call_options: Optional[TxParams], quorum_numbers: List[int], block_number: int
    ) -> List[List[OperatorStateRetrieverOperator]]:
        return self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr, quorum_numbers, block_number
        ).call(call_options)

    def get_operator_addrs_in_quorums_at_current_block(
            self, call_options: Optional[TxParams], quorum_numbers: List[int]
        ) -> List[List[str]]:
        stakes = self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr, quorum_numbers, self.eth_client.eth.block_number
        ).call(call_options)
        return [[op["operator"] for op in quorum] for quorum in stakes]


    def get_operators_stake_in_quorums_of_operator_at_block(
            self, call_options: Optional[TxParams], operator_id: int, block_number: int
        ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        bitmap, stakes = self.operator_state_retriever.functions.getOperatorState0(
            self.registry_coordinator_addr, operator_id, block_number
        ).call(call_options or {})
        return bitmap_to_quorum_ids(bitmap), stakes


    def get_operators_stake_in_quorums_of_operator_at_current_block(
            self, call_options: Optional[TxParams], operator_id: int
        ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        opts = dict(call_options or {})
        opts["block_number"] = self.eth_client.eth.block_number
        return self.get_operators_stake_in_quorums_of_operator_at_block(
            opts, operator_id, opts["block_number"]
        )


    def get_operator_stake_in_quorums_of_operator_at_current_block(
            self, call_options: Optional[TxParams], operator_id: int
        ) -> Optional[Dict[int, int]]:
        opts = dict(call_options or {})
        if "block_hash" not in opts:
            opts.setdefault("block_number", self.eth_client.eth.block_number)

        quorums = bitmap_to_quorum_ids(
            self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(opts)
        )
        return {
            q: self.stake_registry.functions.getCurrentStake(operator_id, q).call(opts)
            for q in quorums
        }


    def weight_of_operator_for_quorum(
            self, call_options: Optional[TxParams], quorum_number: int, operator_addr: str
        ) -> Optional[int]:
        return self.stake_registry.functions.weightOfOperatorForQuorum(
            quorum_number, operator_addr
        ).call(call_options or {})


    def strategy_params_length(
            self, call_options: Optional[TxParams], quorum_number: int
        ) -> Optional[int]:
        return self.stake_registry.functions.strategyParamsLength(quorum_number).call(
            call_options or {}
        )


    def strategy_params_by_index(
            self, call_options: Optional[TxParams], quorum_number: int, index: int
        ) -> Optional[StakeRegistryTypesStrategyParams]:
        return self.stake_registry.functions.strategyParamsByIndex(quorum_number, index).call(
            call_options or {}
        )

        

    def get_stake_history_length(
            self, call_options: Optional[TxParams], operator_id: int, quorum_number: int
        ) -> Optional[int]:
        return self.stake_registry.functions.getStakeHistoryLength(
            operator_id, quorum_number
        ).call(call_options or {})


    def get_stake_history(
        self, call_options: Optional[TxParams], operator_id: int, quorum_number: int
    ) -> Optional[List[StakeRegistryTypesStakeUpdate]]:
        return self.stake_registry.functions.getStakeHistory(
            operator_id, quorum_number
        ).call(call_options or {})


    def get_latest_stake_update(
        self, call_options: Optional[TxParams], operator_id: int, quorum_number: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getLatestStakeUpdate(
            operator_id, quorum_number
        ).call(call_options or {})

        

    def get_stake_update_at_index(
        self, call_options: Optional[TxParams], operator_id: int, quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getStakeUpdateAtIndex(
            quorum_number, operator_id, index
        ).call(call_options or {})

        
    def get_stake_at_block_number(
            self,
            call_options: Optional[TxParams],
            operator_id: int,
            quorum_number: int,
            block_number: int,
        ) -> Optional[int]:
        return self.stake_registry.functions.getStakeAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call(call_options or {})


    def get_stake_update_index_at_block_number(
            self,
            call_options: Optional[TxParams],
            operator_id: int,
            quorum_number: int,
            block_number: int,
        ) -> Optional[int]:
        return self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call(call_options or {})


    def get_stake_at_block_number_and_index(
            self,
            call_options: Optional[TxParams],
            operator_id: int,
            quorum_number: int,
            block_number: int,
            index: int,
        ) -> Optional[int]:
        return self.stake_registry.functions.getStakeAtBlockNumberAndIndex(
            quorum_number, block_number, operator_id, index
        ).call(call_options or {})


    def get_total_stake_history_length(
            self, call_options: Optional[TxParams], quorum_number: int
        ) -> Optional[int]:
        return self.stake_registry.functions.getTotalStakeHistoryLength(quorum_number).call(
            call_options or {}
        )


    def get_check_signatures_indices(
            self,
            call_options: Optional[TxParams],
            reference_block_number: int,
            quorum_numbers: List[int],
            non_signer_operator_ids: List[int],
        ) -> OperatorStateRetrieverCheckSignaturesIndices:
        return self.operator_state_retriever.functions.getCheckSignaturesIndices(
            self.registry_coordinator_addr,
            reference_block_number,
            quorum_numbers,
            non_signer_operator_ids,
        ).call(call_options or {})


    def get_current_total_stake(
            self, call_options: Optional[TxParams], quorum_number: int
        ) -> Optional[int]:
        return self.stake_registry.functions.getCurrentTotalStake(quorum_number).call(
            call_options or {}
        )


    def get_total_stake_update_at_index(
        self, call_options: Optional[TxParams], quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getTotalStakeUpdateAtIndex(
            quorum_number, index
        ).call(call_options or {})


    def get_total_stake_at_block_number_from_index(
        self, call_options: Optional[TxParams], quorum_number: int, block_number: int, index: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(
            quorum_number, block_number, index
        ).call(call_options or {})
        

    def get_total_stake_indices_at_block_number(
            self, call_options: Optional[TxParams], quorum_numbers: List[int], block_number: int
        ) -> Optional[List[int]]:
        return self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(
            block_number, quorum_numbers
        ).call(call_options or {})


    def get_minimum_stake_for_quorum(
            self, call_options: Optional[TxParams], quorum_number: int
        ) -> Optional[int]:
        return self.stake_registry.functions.minimumStakeForQuorum(quorum_number).call(
            call_options or {}
        )


    def get_strategy_params_at_index(
        self, call_options: Optional[TxParams], quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:
        return self.stake_registry.functions.strategyParams(quorum_number, index).call(
            call_options or {}
        )

        

    def get_strategy_per_quorum_at_index(
            self, call_options: Optional[TxParams], quorum_number: int, index: int
        ) -> Optional[str]:
        return self.stake_registry.functions.strategiesPerQuorum(quorum_number, index).call(
            call_options or {}
        )


    def get_restakeable_strategies(self, call_options: Optional[TxParams]) -> List[str]:
        return remove_duplicate_strategies(
            self.service_manager.functions.getRestakeableStrategies().call(call_options or {})
        )


    def get_operator_restaked_strategies(
            self, call_options: Optional[TxParams], operator: str
        ) -> List[str]:
        return remove_duplicate_strategies(
            self.service_manager.functions.getOperatorRestakedStrategies(operator).call(call_options or {})
        )


    def get_stake_type_per_quorum(
        self, call_options: Optional[TxParams], quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.stakeTypePerQuorum(quorum_number).call(call_options or {})

    def get_slashable_stake_look_ahead_per_quorum(
        self, call_options: Optional[TxParams], quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.slashableStakeLookAheadPerQuorum(quorum_number).call(call_options or {})

    def get_operator_id(
        self, call_options: Optional[TxParams], operator_address: str
    ) -> Optional[bytes]:
        return self.registry_coordinator.functions.getOperatorId(operator_address).call(call_options or {})

    def get_operator_from_id(
        self, call_options: Optional[TxParams], operator_id: int
    ) -> Optional[str]:
        return self.registry_coordinator.functions.getOperatorFromId(operator_id).call(call_options or {})

    def query_registration_detail(
            self, call_options: Optional[TxParams], operator_address: str
        ) -> Optional[List[bool]]:
        operator_id = self.get_operator_id(call_options or {}, operator_address)
        if operator_id is None:
            return None

        value = self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(
            call_options or {}
        )
        return [(value & (1 << i)) != 0 for i in range(value.bit_length())]


    def is_operator_registered(
            self, call_options: Optional[TxParams], operator_address: str
        ) -> bool:
        return self.registry_coordinator.functions.getOperatorStatus(operator_address).call(
            call_options or {}
        ) == 1


    def is_operator_set_quorum(
            self, call_options: Optional[TxParams], quorum_number: int
        ) -> Optional[bool]:
        return self.stake_registry.functions.isOperatorSetQuorum(quorum_number).call(
            call_options or {}
        )

    def get_operator_id_from_operator_address(
            self, call_options: Optional[TxParams], operator_address: str
        ) -> Optional[bytes]:
        return self.bls_apk_registry.functions.operatorToPubkeyHash(operator_address).call(
            call_options or {}
        )


    def get_operator_address_from_operator_id(
            self, call_options: Optional[TxParams], operator_pubkey_hash: bytes
        ) -> Optional[str]:
        return self.bls_apk_registry.functions.pubkeyHashToOperator(operator_pubkey_hash).call(
            call_options or {}
        )


    def get_pubkey_from_operator_address(
            self, call_options: Optional[TxParams], operator_address: str
        ) -> Optional[G1Point]:
        operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(operator_address).call(
            call_options or {}
        )
        return G1Point(operator_pubkey["x"], operator_pubkey["y"])


    def get_apk_update(
            self, call_options: Optional[TxParams], quorum_number: int, index: int
        ) -> Optional[BLSApkRegistryTypesApkUpdate]:
        update = self.bls_apk_registry.functions.apkHistory(quorum_number, index).call(
            call_options or {}
        )
        return BLSApkRegistryTypesApkUpdate(
            apk_hash=bytes(update["apkHash"]),
            update_block_number=update["updateBlockNumber"],
            next_update_block_number=update["nextUpdateBlockNumber"],
        )


    def get_current_apk(
            self, call_options: Optional[dict], quorum_number: int
        ) -> Optional[G1Point]:
        apk = self.bls_apk_registry.functions.currentApk(quorum_number).call(call_options or {})
        return G1Point(apk["x"], apk["y"])


    def query_existing_registered_operator_sockets(
            self, start_block: Optional[int], stop_block: Optional[int], block_range: Optional[int]
        ) -> Optional[Dict[bytes, str]]:
        start_block = start_block or 0
        stop_block = stop_block or self.eth_client.eth.block_number
        block_range = block_range or DEFAULT_QUERY_BLOCK_RANGE

        operator_id_to_socket_map = {}
        for i in range(start_block, stop_block + 1, block_range):
            to_block = min(i + block_range - 1, stop_block)
            filter_opts = {"fromBlock": i, "toBlock": to_block}

            socket_updates = self.registry_coordinator.events.OperatorSocketUpdate().get_logs(
                filter_opts
            )
            num_socket_updates = 0
            for event in socket_updates:
                args = event["args"]
                operator_id_raw = args.get("operatorId")

                operator_id = bytes.fromhex(operator_id_raw[2:] if operator_id_raw.startswith("0x") else operator_id_raw)

                operator_id_to_socket_map[operator_id] = str(args.get("socket", ""))
                num_socket_updates += 1

            self.logger.debug(
                "avs_registry_chain_reader.query_existing_registered_operator_sockets",
                extra={
                    "numTransactionLogs": num_socket_updates,
                    "fromBlock": i,
                    "toBlock": to_block,
                },
            )

        return operator_id_to_socket_map

