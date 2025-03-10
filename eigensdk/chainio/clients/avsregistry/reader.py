import logging
import math
from typing import Dict, List, Optional, Tuple

from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract

from eigensdk._types import (
    OperatorPubkeys,
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
)
from eigensdk.chainio import utils
from eigensdk.crypto.bls.attestation import G1Point, G2Point

DEFAULT_QUERY_BLOCK_RANGE = 10_000


class AvsRegistryReader:
    def __init__(
        self,
        registry_coordinator: Contract,
        bls_apk_registry: Contract,
        operator_state_retriever: Contract,
        service_manager: Contract,
        stake_registry: Contract,
        logger: logging.Logger,
        eth_http_client: Web3,
        
    ):
        self.logger: logging.Logger = logger
        self.bls_apk_registry: Contract = bls_apk_registry
        self.registry_coordinator: Contract = registry_coordinator
        self.operator_state_retriever: Contract = operator_state_retriever
        self.stake_registry: Contract = stake_registry
        self.eth_http_client: Web3 = eth_http_client
        

    def get_quorum_count(self, call_options: Optional[dict] = None) -> Tuple[int, Optional[Exception]]:
        if self.registry_coordinator is None:
            return 0, ValueError("RegistryCoordinator contract not provided")

        try:
            return self.registry_coordinator.functions.quorumCount().call(call_options), None
        except Exception as e:
            return 0, e

    

    def get_operators_stake_in_quorums_at_current_block(
        self, call_options: Optional[dict], quorum_numbers: List[QuorumNum]
    ) -> Tuple[List[List[OperatorStateRetrieverOperator]], Optional[Exception]]:
        try:
            context = call_options.get("context", None)
            if context is None:
                context = {}

            cur_block = self.eth_client.eth.block_number
            if cur_block > (2**32 - 1):
                return None, ValueError("Current block number is too large to be converted to uint32")

            return self.get_operators_stake_in_quorums_at_block(call_options, quorum_numbers, int(cur_block)), None
        except Exception as e:
            return None, e

    def get_operators_stake_in_quorums_at_block(
        self, call_options: Optional[dict], quorum_numbers: List[QuorumNum], block_number: int
    ) -> Tuple[Optional[List[List[OperatorStateRetrieverOperator]]], Optional[Exception]]:
        if self.operator_state_retriever is None:
            return None, ValueError("OperatorStateRetriever contract not provided")

        try:
            operator_stakes = self.operator_state_retriever.functions.getOperatorState(
                self.registry_coordinator_addr,
                quorum_numbers.underlying_type(),
                block_number
            ).call(call_options)

            return operator_stakes, None
        except Exception as e:
            return None, e

    def get_operator_addrs_in_quorums_at_current_block(
        self, call_options: Optional[dict], quorum_numbers: List[QuorumNum]
    ) -> Tuple[Optional[List[List[str]]], Optional[Exception]]:
        if self.operator_state_retriever is None:
            return None, ValueError("OperatorStateRetriever contract not provided")

        try:
            context = call_options.get("context", None)
            if context is None:
                context = {}

            cur_block = self.eth_client.eth.block_number
            if cur_block > (2**32 - 1):
                return None, ValueError("Current block number is too large to be converted to uint32")

            operator_stakes = self.operator_state_retriever.functions.getOperatorState(
                self.registry_coordinator_addr,
                quorum_numbers.underlying_type(),
                int(cur_block)
            ).call(call_options)

            quorum_operator_addrs = [
                [operator["operator"] for operator in quorum] for quorum in operator_stakes
            ]

            return quorum_operator_addrs, None
        except Exception as e:
            return None, e

    def get_operators_stake_in_quorums_of_operator_at_block(
        self, call_options: Optional[dict], operator_id: OperatorId, block_number: int
    ) -> Tuple[Optional[List[QuorumNum]], Optional[List[List[OperatorStateRetrieverOperator]]], Optional[Exception]]:
        if self.operator_state_retriever is None:
            return None, None, ValueError("OperatorStateRetriever contract not provided")

        try:
            quorum_bitmap, operator_stakes = self.operator_state_retriever.functions.getOperatorState0(
                self.registry_coordinator_addr,
                operator_id,
                block_number
            ).call(call_options)

            quorums = bitmap_to_quorum_ids(quorum_bitmap)

            return quorums, operator_stakes, None
        except Exception as e:
            return None, None, e


    def get_operators_stake_in_quorums_of_operator_at_current_block(
        self, call_options: Optional[dict], operator_id: OperatorId
    ) -> Tuple[Optional[List[QuorumNum]], Optional[List[List[OperatorStateRetrieverOperator]]], Optional[Exception]]:
        try:
            context = call_options.get("context", None)
            if context is None:
                context = {}

            cur_block = self.eth_client.eth.block_number
            if cur_block > (2**32 - 1):
                return None, None, ValueError("Current block number is too large to be converted to uint32")

            call_options["block_number"] = cur_block

            return self.get_operators_stake_in_quorums_of_operator_at_block(call_options, operator_id, int(cur_block))
        except Exception as e:
            return None, None, e

    
    def get_operator_stake_in_quorums_of_operator_at_current_block(
        self, call_options: Optional[dict], operator_id: OperatorId
    ) -> Tuple[Optional[Dict[QuorumNum, StakeAmount]], Optional[Exception]]:
        if self.registry_coordinator is None:
            return None, ValueError("RegistryCoordinator contract not provided")

        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            if "block_number" not in call_options and "block_hash" not in call_options:
                latest_block = self.eth_client.eth.block_number
                call_options["block_number"] = latest_block

            quorum_bitmap = self.registry_coordinator.functions.getCurrentQuorumBitmap(
                operator_id
            ).call(call_options)

            quorums = bitmap_to_quorum_ids(quorum_bitmap)
            quorum_stakes = {}

            for quorum in quorums:
                stake = self.stake_registry.functions.getCurrentStake(
                    operator_id,
                    int(quorum)
                ).call(call_options)

                quorum_stakes[quorum] = stake

            return quorum_stakes, None
        except Exception as e:
            return None, e

    def weight_of_operator_for_quorum(
        self, call_options: Optional[dict], quorum_number: int, operator_addr: str
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.weightOfOperatorForQuorum(
                quorum_number, operator_addr
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def strategy_params_length(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            length = self.stake_registry.functions.strategyParamsLength(
                quorum_number
            ).call(call_options)

            return length, None
        except Exception as e:
            return None, e
    
    def strategy_params_by_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[StakeRegistryTypesStrategyParams], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            param = self.stake_registry.functions.strategyParamsByIndex(
                quorum_number, index
            ).call(call_options)

            return param, None
        except Exception as e:
            return None, e
    
    def get_stake_history_length(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            length = self.stake_registry.functions.getStakeHistoryLength(
                operator_id, quorum_number
            ).call(call_options)

            return length, None
        except Exception as e:
            return None, e

    def get_stake_history(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int
    ) -> Tuple[Optional[List[StakeRegistryTypesStakeUpdate]], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake_history = self.stake_registry.functions.getStakeHistory(
                operator_id, quorum_number
            ).call(call_options)

            return stake_history, None
        except Exception as e:
            return None, e


    def get_latest_stake_update(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int
    ) -> Tuple[Optional[StakeRegistryTypesStakeUpdate], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake_update = self.stake_registry.functions.getLatestStakeUpdate(
                operator_id, quorum_number
            ).call(call_options)

            return stake_update, None
        except Exception as e:
            return None, e

    def get_stake_update_at_index(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int, index: int
    ) -> Tuple[Optional[StakeRegistryTypesStakeUpdate], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake_update = self.stake_registry.functions.getStakeUpdateAtIndex(
                quorum_number, operator_id, index
            ).call(call_options)

            return stake_update, None
        except Exception as e:
            return None, e

    def get_stake_at_block_number(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int, block_number: int
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.getStakeAtBlockNumber(
                operator_id, quorum_number, block_number
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def get_stake_update_index_at_block_number(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int, block_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            index = self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(
                operator_id, quorum_number, block_number
            ).call(call_options)

            return index, None
        except Exception as e:
            return None, e

    
    def get_stake_at_block_number_and_index(
        self, call_options: Optional[dict], operator_id: OperatorId, quorum_number: int, block_number: int, index: int
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.getStakeAtBlockNumberAndIndex(
                quorum_number, block_number, operator_id, index
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def get_total_stake_history_length(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            length = self.stake_registry.functions.getTotalStakeHistoryLength(
                quorum_number
            ).call(call_options)

            return length, None
        except Exception as e:
            return None, e
    
    def get_check_signatures_indices(
        self, call_options: Optional[dict], reference_block_number: int, quorum_numbers: List[QuorumNum], non_signer_operator_ids: List[OperatorId]
    ) -> Tuple[Optional[OperatorStateRetrieverCheckSignaturesIndices], Optional[Exception]]:
        if self.operator_state_retriever is None:
            return None, ValueError("OperatorStateRetriever contract not provided")

        try:
            non_signer_operator_ids_bytes = [operator_id for operator_id in non_signer_operator_ids]

            check_signature_indices = self.operator_state_retriever.functions.getCheckSignaturesIndices(
                self.registry_coordinator_addr,
                reference_block_number,
                quorum_numbers.underlying_type(),
                non_signer_operator_ids_bytes
            ).call(call_options)

            return check_signature_indices, None
        except Exception as e:
            return None, e

    def get_current_total_stake(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.getCurrentTotalStake(
                quorum_number
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def get_total_stake_update_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[StakeRegistryTypesStakeUpdate], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake_update = self.stake_registry.functions.getTotalStakeUpdateAtIndex(
                quorum_number, index
            ).call(call_options)

            return stake_update, None
        except Exception as e:
            return None, e

    def get_total_stake_at_block_number_from_index(
        self, call_options: Optional[dict], quorum_number: int, block_number: int, index: int
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(
                quorum_number, block_number, index
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def get_total_stake_indices_at_block_number(
        self, call_options: Optional[dict], quorum_numbers: List[QuorumNum], block_number: int
    ) -> Tuple[Optional[List[int]], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            indices = self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(
                block_number, quorum_numbers.underlying_type()
            ).call(call_options)

            return indices, None
        except Exception as e:
            return None, e

    
    def get_minimum_stake_for_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[StakeAmount], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake = self.stake_registry.functions.minimumStakeForQuorum(
                quorum_number
            ).call(call_options)

            return stake, None
        except Exception as e:
            return None, e

    def get_strategy_params_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[StakeRegistryTypesStrategyParams], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            params = self.stake_registry.functions.strategyParams(
                quorum_number, index
            ).call(call_options)

            return params, None
        except Exception as e:
            return None, e

    
    def get_strategy_per_quorum_at_index(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[str], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            strategy = self.stake_registry.functions.strategiesPerQuorum(
                quorum_number, index
            ).call(call_options)

            return strategy, None
        except Exception as e:
            return None, e
    
    def get_restakeable_strategies(
        self, call_options: Optional[dict]
    ) -> Tuple[Optional[List[str]], Optional[Exception]]:
        if self.service_manager is None:
            return None, ValueError("ServiceManager contract not provided")

        try:
            strategies = self.service_manager.functions.getRestakeableStrategies().call(call_options)

            if not strategies:
                return strategies, None

            return remove_duplicate_strategies(strategies), None
        except Exception as e:
            return None, e

    def get_operator_restaked_strategies(
        self, call_options: Optional[dict], operator: str
    ) -> Tuple[Optional[List[str]], Optional[Exception]]:
        if self.service_manager is None:
            return None, ValueError("ServiceManager contract not provided")

        try:
            strategies = self.service_manager.functions.getOperatorRestakedStrategies(
                operator
            ).call(call_options)

            return remove_duplicate_strategies(strategies), None
        except Exception as e:
            return None, e
    
    def get_stake_type_per_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            stake_type = self.stake_registry.functions.stakeTypePerQuorum(
                quorum_number
            ).call(call_options)

            return stake_type, None
        except Exception as e:
            return None, e
    
    

    def get_slashable_stake_look_ahead_per_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            look_ahead = self.stake_registry.functions.slashableStakeLookAheadPerQuorum(
                quorum_number
            ).call(call_options)

            return look_ahead, None
        except Exception as e:
            return None, e

    def get_operator_id(
        self, call_options: Optional[dict], operator_address: str
    ) -> Tuple[Optional[bytes], Optional[Exception]]:
        if self.registry_coordinator is None:
            return None, ValueError("RegistryCoordinator contract not provided")

        try:
            operator_id = self.registry_coordinator.functions.getOperatorId(
                operator_address
            ).call(call_options)

            return operator_id, None
        except Exception as e:
            return None, e

    def get_operator_from_id(
        self, call_options: Optional[dict], operator_id: OperatorId
    ) -> Tuple[Optional[str], Optional[Exception]]:
        if self.registry_coordinator is None:
            return None, ValueError("RegistryCoordinator contract not provided")

        try:
            operator_address = self.registry_coordinator.functions.getOperatorFromId(
                operator_id
            ).call(call_options)

            return operator_address, None
        except Exception as e:
            return None, e

    def query_registration_detail(
        self, call_options: Optional[dict], operator_address: str
    ) -> Tuple[Optional[List[bool]], Optional[Exception]]:
        try:
            operator_id, err = self.get_operator_id(call_options, operator_address)
            if err:
                return None, ValueError("Failed to get operator id")

            value = self.registry_coordinator.functions.getCurrentQuorumBitmap(
                operator_id
            ).call(call_options)

            num_bits = value.bit_length()
            quorums = [(value & (1 << i)) != 0 for i in range(num_bits)]

            if not quorums:
                num_quorums, err = self.get_quorum_count(call_options)
                if err:
                    return None, ValueError("Failed to get quorum count")
                quorums = [False] * num_quorums

            return quorums, None
        except Exception as e:
            return None, e

    
    def is_operator_registered(
        self, call_options: Optional[dict], operator_address: str
    ) -> Tuple[Optional[bool], Optional[Exception]]:
        if self.registry_coordinator is None:
            return None, ValueError("RegistryCoordinator contract not provided")

        try:
            operator_status = self.registry_coordinator.functions.getOperatorStatus(
                operator_address
            ).call(call_options)

            registered_with_avs = operator_status == 1

            return registered_with_avs, None
        except Exception as e:
            return None, e

    def is_operator_set_quorum(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[bool], Optional[Exception]]:
        if self.stake_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            is_operator_set = self.stake_registry.functions.isOperatorSetQuorum(
                quorum_number
            ).call(call_options)

            return is_operator_set, None
        except Exception as e:
            return None, e

    def get_operator_id_from_operator_address(
        self, call_options: Optional[dict], operator_address: str
    ) -> Tuple[Optional[bytes], Optional[Exception]]:
        if self.bls_apk_registry is None:
            return None, ValueError("BLSApkRegistry contract not provided")

        try:
            operator_pubkey_hash = self.bls_apk_registry.functions.operatorToPubkeyHash(
                operator_address
            ).call(call_options)

            return operator_pubkey_hash, None
        except Exception as e:
            return None, e

    
    def get_operator_address_from_operator_id(
        self, call_options: Optional[dict], operator_pubkey_hash: bytes
    ) -> Tuple[Optional[str], Optional[Exception]]:
        if self.bls_apk_registry is None:
            return None, ValueError("BLSApkRegistry contract not provided")

        try:
            operator_address = self.bls_apk_registry.functions.pubkeyHashToOperator(
                operator_pubkey_hash
            ).call(call_options)

            return operator_address, None
        except Exception as e:
            return None, e

    def get_pubkey_from_operator_address(
        self, call_options: Optional[dict], operator_address: str
    ) -> Tuple[Optional[G1Point], Optional[Exception]]:
        if self.bls_apk_registry is None:
            return None, ValueError("BLSApkRegistry contract not provided")

        try:
            operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(
                operator_address
            ).call(call_options)

            operator_pubkey_g1 = G1Point(operator_pubkey["x"], operator_pubkey["y"])

            return operator_pubkey_g1, None
        except Exception as e:
            return None, e

    def get_apk_update(
        self, call_options: Optional[dict], quorum_number: int, index: int
    ) -> Tuple[Optional[BLSApkRegistryTypesApkUpdate], Optional[Exception]]:
        if self.bls_apk_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            update = self.bls_apk_registry.functions.apkHistory(
                quorum_number, index
            ).call(call_options)

            apk_update = BLSApkRegistryTypesApkUpdate(
                apk_hash=update["apkHash"],
                update_block_number=update["updateBlockNumber"],
                next_update_block_number=update["nextUpdateBlockNumber"],
            )

            return apk_update, None
        except Exception as e:
            return None, e

    def get_current_apk(
        self, call_options: Optional[dict], quorum_number: int
    ) -> Tuple[Optional[G1Point], Optional[Exception]]:
        if self.bls_apk_registry is None:
            return None, ValueError("StakeRegistry contract not provided")

        try:
            apk = self.bls_apk_registry.functions.currentApk(
                quorum_number
            ).call(call_options)

            apk_g1 = G1Point(apk["x"], apk["y"])

            return apk_g1, None
        except Exception as e:
            return None, e

    def query_existing_registered_operator_pub_keys(
        self, context: Any, start_block: Optional[int], stop_block: Optional[int], block_range: Optional[int]
    ) -> Tuple[Optional[List[str]], Optional[List[OperatorPubkeys]], Optional[Exception]]:
        try:
            bls_apk_registry_abi = self.bls_apk_registry_abi
            if bls_apk_registry_abi is None:
                return None, None, ValueError("Cannot get ABI")

            if start_block is None:
                start_block = 0
            if stop_block is None:
                stop_block = self.eth_client.eth.block_number
            if block_range is None:
                block_range = DEFAULT_QUERY_BLOCK_RANGE

            operator_addresses = []
            operator_pubkeys = []

            i = start_block
            while i <= stop_block:
                to_block = min(i + block_range - 1, stop_block)

                query = {
                    "fromBlock": i,
                    "toBlock": to_block,
                    "address": [self.bls_apk_registry_addr],
                    "topics": [[bls_apk_registry_abi.events["NewPubkeyRegistration"].signature]],
                }

                logs = self.eth_client.eth.get_logs(query)

                self.logger.debug(
                    "avs_registry_chain_reader.query_existing_registered_operator_pub_keys",
                    extra={
                        "numTransactionLogs": len(logs),
                        "fromBlock": i,
                        "toBlock": to_block,
                    },
                )

                for log in logs:
                    operator_addr = self.web3.to_checksum_address(log["topics"][1].hex())
                    operator_addresses.append(operator_addr)

                    event = bls_apk_registry_abi.events["NewPubkeyRegistration"]().process_log(log)

                    G1_pubkey = event["args"]["G1Pubkey"]
                    G2_pubkey = event["args"]["G2Pubkey"]

                    operator_pubkey = OperatorPubkeys(
                        g1_pubkey=G1Point(G1_pubkey["X"], G1_pubkey["Y"]),
                        g2_pubkey=G2Point(G2_pubkey["X"], G2_pubkey["Y"]),
                    )

                    operator_pubkeys.append(operator_pubkey)

                i += block_range

            return operator_addresses, operator_pubkeys, None
        except Exception as e:
            return None, None, e

    def query_existing_registered_operator_sockets(
        self, context: Any, start_block: Optional[int], stop_block: Optional[int], block_range: Optional[int]
    ) -> Tuple[Optional[Dict[OperatorId, Socket]], Optional[Exception]]:
        if self.registry_coordinator is None:
            return None, ValueError("RegistryCoordinator contract not provided")

        try:
            if start_block is None:
                start_block = 0
            if stop_block is None:
                stop_block = self.eth_client.eth.block_number
            if block_range is None:
                block_range = DEFAULT_QUERY_BLOCK_RANGE

            operator_id_to_socket_map = {}

            i = start_block
            while i <= stop_block:
                to_block = min(i + block_range - 1, stop_block)

                filter_opts = {
                    "fromBlock": i,
                    "toBlock": to_block
                }

                socket_updates = self.registry_coordinator.events.OperatorSocketUpdate().get_logs(filter_opts)

                num_socket_updates = 0
                for event in socket_updates:
                    operator_id = event["args"]["operatorId"]
                    socket = event["args"]["socket"]
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

            return operator_id_to_socket_map, None
        except Exception as e:
            return None, e

    def remove_duplicate_strategies(strategies: List[str]) -> List[str]:
        if not strategies:
            return []

        strategies = sorted(strategies)
        unique_strategies = [strategies[0]]

        for strategy in strategies[1:]:
            if strategy != unique_strategies[-1]:
                unique_strategies.append(strategy)

        return unique_strategies
