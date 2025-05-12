import logging
import math
from eth_typing import Address
from typing import Dict, List, Optional, Tuple
from typing import cast
from web3 import Web3
from web3.contract.contract import Contract
from web3.types import TxParams
from web3._utils.events import get_event_data
from eth_utils import event_abi_to_log_topic
from eigensdk.chainio import utils

from eigensdk._types import (
    OperatorPubkeys,
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
)

from eigensdk._types import (
    StakeRegistryTypesStrategyParams,
    StakeRegistryTypesStakeUpdate,
    BLSApkRegistryTypesApkUpdate,
)
from eigensdk.chainio.utils import bitmap_to_quorum_ids, remove_duplicate_strategies
from eigensdk.crypto.bls.attestation import G1Point, G2Point
from eth_account.signers.local import LocalAccount

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
        eth_http_client: Web3,
        pk_wallet: LocalAccount,
    ):

        self.logger: logging.Logger = logger
        self.bls_apk_registry: Contract = bls_apk_registry
        self.bls_apk_registry_addr = bls_apk_registry_addr
        self.registry_coordinator: Contract = registry_coordinator
        self.registry_coordinator_addr = registry_coordinator_addr
        self.operator_state_retriever: Contract = operator_state_retriever
        self.service_manager = service_manager
        self.stake_registry: Contract = stake_registry
        self.eth_http_client: Web3 = eth_http_client
        self.pk_wallet: LocalAccount = pk_wallet

        if registry_coordinator is None:
            self.logger.warning("RegistryCoordinator contract not provided")

        if registry_coordinator_addr is None:
            self.logger.warning("RegistryCoordinator address not provided")

        if bls_apk_registry is None:
            self.logger.warning("BLSApkRegistry contract not provided")

        if bls_apk_registry_addr is None:
            self.logger.warning("BLSApkRegistry address not provided")

        if operator_state_retriever is None:
            self.logger.warning("OperatorStateRetriever contract not provided")

        if service_manager is None:
            self.logger.warning("ServiceManager contract not provided")

        if stake_registry is None:
            self.logger.warning("StakeRegistry contract not provided")

        if eth_http_client is None:
            self.logger.warning("EthHTTPClient not provided")

        if pk_wallet is None:
            self.logger.warning("PKWallet not provided")

    def get_quorum_count(self) -> int:
        return self.registry_coordinator.functions.quorumCount().call()

    def get_operators_stake_in_quorums_at_current_block(
        self, quorum_numbers: List[int]
    ) -> List[List[OperatorStateRetrieverOperator]]:
        cur_block = self.eth_http_client.eth.block_number
        if cur_block > math.pow(2, 32) - 1:
            raise ValueError("Current block number is too large to be converted to uint32")
        return self.get_operators_stake_in_quorums_at_block(quorum_numbers, cur_block)

    def get_operators_stake_in_quorums_at_block(
        self, quorum_numbers: List[int], block_number: int
    ) -> List[List[OperatorStateRetrieverOperator]]:
        operator_stakes = self.operator_state_retriever.functions.getOperatorState(
            registryCoordinator=self.registry_coordinator_addr,
            quorumNumbers=utils.nums_to_bytes(quorum_numbers),
            blockNumber=block_number,
        ).call()
        return [
            [
                OperatorStateRetrieverOperator(
                    operator=operator[0],
                    operator_id="0x" + operator[1].hex(),
                    stake=operator[2],
                )
                for operator in quorum
            ]
            for quorum in operator_stakes
        ]

    def get_operator_addrs_in_quorums_at_current_block(
        self, quorum_numbers: List[int]
    ) -> List[List[str]]:
        stakes = self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr, utils.nums_to_bytes(quorum_numbers), self.eth_http_client.eth.block_number
        ).call()
        return [
            [op[0] for op in quorum] for quorum in stakes
        ]  

    def get_operators_stake_in_quorums_of_operator_at_block(
        self,  operator_id: int, block_number: int
    ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        bitmap, stakes = self.operator_state_retriever.functions.getOperatorState(
            self.registry_coordinator_addr, utils.nums_to_bytes(operator_id), block_number
        ).call()
        return bitmap_to_quorum_ids(bitmap), stakes

    def get_operators_stake_in_quorums_of_operator_at_current_block(
        self, operator_id: int
    ) -> Tuple[Optional[List[int]], Optional[List[List[OperatorStateRetrieverOperator]]]]:
        block_number = self.eth_http_client.eth.block_number
        return self.get_operators_stake_in_quorums_of_operator_at_block(
            operator_id, block_number
        )

    def get_operator_stake_in_quorums_of_operator_at_current_block(
        self,  operator_id: int
    ) -> Optional[Dict[int, int]]:
        opts = {}

        if "block_hash" not in opts: 
            opts["block_identifier"] = self.eth_http_client.eth.block_number

        tx_params = cast(TxParams, opts) 

        quorums = bitmap_to_quorum_ids(
            self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call(tx_params)
        )
        return {
            q: self.stake_registry.functions.getCurrentStake(operator_id, q).call(tx_params)
            for q in quorums
        }

    def weight_of_operator_for_quorum(
        self,  quorum_number: int, operator_addr: str
    ) -> Optional[int]:
        return self.stake_registry.functions.weightOfOperatorForQuorum(
            quorum_number, operator_addr
        ).call()

    def strategy_params_length(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.strategyParamsLength(quorum_number).call()

    def strategy_params_by_index(
        self,  quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:
        return self.stake_registry.functions.strategyParamsByIndex(quorum_number, index).call()

    def get_stake_history_length(
        self,  operator_id: int, quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getStakeHistoryLength(operator_id, quorum_number).call()

    def get_stake_history(
        self,  operator_id: int, quorum_number: int
    ) -> Optional[List[StakeRegistryTypesStakeUpdate]]:
        return self.stake_registry.functions.getStakeHistory(operator_id, quorum_number).call()

    def get_latest_stake_update(
        self,  operator_id: int, quorum_number: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getLatestStakeUpdate(operator_id, quorum_number).call()

    def get_stake_update_at_index(
        self,  operator_id: int, quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getStakeUpdateAtIndex(
            quorum_number, operator_id, index
        ).call()

    def get_stake_at_block_number(
        self,
        
        operator_id: int,
        quorum_number: int,
        block_number: int,
    ) -> Optional[int]:
        return self.stake_registry.functions.getStakeAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call()

    def get_stake_update_index_at_block_number(
        self,
        
        operator_id: int,
        quorum_number: int,
        block_number: int,
    ) -> Optional[int]:
        return self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call()

    def get_stake_at_block_number_and_index(
        self,
        
        operator_id: int,
        quorum_number: int,
        block_number: int,
        index: int,
    ) -> Optional[int]:
        return self.stake_registry.functions.getStakeAtBlockNumberAndIndex(
            quorum_number, block_number, operator_id, index
        ).call()

    def get_total_stake_history_length(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getTotalStakeHistoryLength(quorum_number).call()

    def get_check_signatures_indices(
        self,
        
        reference_block_number: int,
        quorum_numbers: List[int],
        non_signer_operator_ids: List[int],
    ) -> OperatorStateRetrieverCheckSignaturesIndices:
        return self.operator_state_retriever.functions.getCheckSignaturesIndices(
            self.registry_coordinator_addr,
            reference_block_number,
            quorum_numbers,
            non_signer_operator_ids,
        ).call()

    def get_current_total_stake(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getCurrentTotalStake(quorum_number).call(call_options)

    def get_total_stake_update_at_index(
        self,  quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getTotalStakeUpdateAtIndex(quorum_number, index).call()

    def get_total_stake_at_block_number_from_index(
        self,  quorum_number: int, block_number: int, index: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(
            quorum_number, block_number, index
        ).call()

    def get_total_stake_indices_at_block_number(
        self,  quorum_numbers: List[int], block_number: int
    ) -> Optional[List[int]]:
        return self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(
            block_number, quorum_numbers
        ).call()

    def get_minimum_stake_for_quorum(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.minimumStakeForQuorum(quorum_number).call(call_options)

    def get_strategy_params_at_index(
        self,  quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:
        return self.stake_registry.functions.strategyParams(quorum_number, index).call(call_options)

    def get_strategy_per_quorum_at_index(
        self,  quorum_number: int, index: int
    ) -> Optional[str]:
        return self.stake_registry.functions.strategiesPerQuorum(quorum_number, index).call()

    def get_restakeable_strategies(self, call_options: Optional[TxParams]) -> List[str]:
        return remove_duplicate_strategies(
            self.service_manager.functions.getRestakeableStrategies().call(call_options)
        )

    def get_operator_restaked_strategies(
        self,  operator: str
    ) -> List[str]:
        return remove_duplicate_strategies(
            self.service_manager.functions.getOperatorRestakedStrategies(operator).call()
        )

    def get_stake_type_per_quorum(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.stakeTypePerQuorum(quorum_number).call(call_options)

    def get_slashable_stake_look_ahead_per_quorum(
        self,  quorum_number: int
    ) -> Optional[int]:
        return self.stake_registry.functions.slashableStakeLookAheadPerQuorum(quorum_number).call()

    def get_operator_id(self, operator_address: Address) -> bytes:
        operator_id = self.registry_coordinator.functions.getOperatorId(operator_address).call()
        return operator_id

    def get_operator_from_id(
        self,  operator_id: int
    ) -> Optional[str]:
        return self.registry_coordinator.functions.getOperatorFromId(operator_id).call(call_options)

    def query_registration_detail(
        self,  operator_address: Address
    ) -> Optional[List[bool]]:
        operator_id = self.get_operator_id(operator_address=operator_address)
        if operator_id is None:
            return None

        value = self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call()
        return [(value & (1 << i)) != 0 for i in range(value.bit_length())]

    def is_operator_registered(
        self,  operator_address: str
    ) -> bool:
        return (
            self.registry_coordinator.functions.getOperatorStatus(operator_address).call()
            == 1
        )

    def is_operator_set_quorum(
        self,  quorum_number: int
    ) -> Optional[bool]:
        return self.stake_registry.functions.isOperatorSetQuorum(quorum_number).call()

    def get_operator_id_from_operator_address(
        self,  operator_address: str
    ) -> Optional[bytes]:
        return self.bls_apk_registry.functions.operatorToPubkeyHash(operator_address).call()

    def get_operator_address_from_operator_id(
        self,  operator_pubkey_hash: bytes
    ) -> Optional[str]:
        return self.bls_apk_registry.functions.pubkeyHashToOperator(operator_pubkey_hash).call()

    def get_pubkey_from_operator_address(
        self,  operator_address: str
    ) -> Optional[G1Point]:
        operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(operator_address).call()
        return G1Point(operator_pubkey[0], operator_pubkey[1])

    def get_apk_update(
        self,  quorum_number: int, index: int
    ) -> Optional[BLSApkRegistryTypesApkUpdate]:
        update = self.bls_apk_registry.functions.apkHistory(quorum_number, index).call()
        return BLSApkRegistryTypesApkUpdate(
            apk_hash=bytes(update["apkHash"]),
            update_block_number=update["updateBlockNumber"],
            next_update_block_number=update["nextUpdateBlockNumber"],
        )

    def get_current_apk(
        self,  quorum_number: int
    ) -> Optional[G1Point]:
        apk = self.bls_apk_registry.functions.currentApk(quorum_number).call()
        return G1Point(apk["x"], apk["y"])

    def query_existing_registered_operator_sockets(
        self,
        start_block: int = 0,
        stop_block: Optional[int] = None,
        block_range: int = DEFAULT_QUERY_BLOCK_RANGE,
    ) -> Tuple[Dict[bytes, str], int]:
        if stop_block is None:
            stop_block = self.eth_http_client.eth.block_number

        operator_id_to_socket_map: Dict[bytes, str] = {}

        event_abi = self.registry_coordinator.events.OperatorSocketUpdate._get_event_abi()
        event_topic = event_abi_to_log_topic(event_abi)

        for i in range(start_block, stop_block + 1, block_range):
            to_block = min(i + block_range - 1, stop_block)

            try:
                logs = self.eth_http_client.eth.get_logs(
                    {
                        "fromBlock": i,
                        "toBlock": to_block,
                        "address": self.registry_coordinator.address,
                        "topics": [Web3.to_hex(event_topic)],
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to fetch logs for blocks {i}-{to_block}: {e}")
                continue

            decoded_logs = [
                get_event_data(self.eth_http_client.codec, event_abi, log) for log in logs
            ]

            for log in decoded_logs:
                operator_id_raw = log["args"]["operatorId"]
                socket = log["args"]["socket"]

                # Normalize operator ID
                operator_id = (
                    bytes.fromhex(operator_id_raw[2:])
                    if operator_id_raw.startswith("0x")
                    else bytes.fromhex(operator_id_raw)
                )

                operator_id_to_socket_map[operator_id] = socket

            self.logger.debug(
                "avsRegistryChainReader.query_existing_registered_operator_sockets",
                extra={
                    "numTransactionLogs": len(decoded_logs),
                    "fromBlock": i,
                    "toBlock": to_block,
                },
            )

        return operator_id_to_socket_map, stop_block

    def query_existing_registered_operator_pubkeys(
        self,
        start_block: int = 0,
        stop_block: Optional[int] = None,
        block_range: int = DEFAULT_QUERY_BLOCK_RANGE,
    ) -> Tuple[List[Address], List[OperatorPubkeys], int]:
        if stop_block is None:
            stop_block = self.eth_http_client.eth.block_number

        operator_pubkeys: List[OperatorPubkeys] = []
        operator_addresses: List[Address] = []
        for i in range(start_block, stop_block + 1, block_range):
            to_block: int = min(i + block_range - 1, stop_block)

            event_abi = self.bls_apk_registry.events.NewPubkeyRegistration._get_event_abi()
            event_topic = event_abi_to_log_topic(event_abi)
            logs = self.eth_http_client.eth.get_logs(
                {
                    "fromBlock": i,
                    "toBlock": to_block,
                    "address": self.bls_apk_registry.address,
                    "topics": [Web3.to_hex(event_topic)],
                }
            )

            pubkey_updates = [
                get_event_data(self.eth_http_client.codec, event_abi, log) for log in logs
            ]

            self.logger.debug(
                "avsRegistryChainReader.query_existing_registered_operator_pubkeys",
                extra={
                    "numTransactionLogs": len(pubkey_updates),
                    "fromBlock": i,
                    "toBlock": to_block,
                },
            )
            for update in pubkey_updates:
                operator_addr = update["args"]["operator"]
                pubkey_g1 = update["args"]["pubkeyG1"]
                pubkey_g2 = update["args"]["pubkeyG2"]
                operator_pubkeys.append(
                    OperatorPubkeys(
                        g1_pub_key=G1Point(pubkey_g1["X"], pubkey_g1["Y"]),
                        g2_pub_key=G2Point(*pubkey_g2["X"], *pubkey_g2["Y"]),
                    )
                )
                operator_addresses.append(operator_addr)
        return operator_addresses, operator_pubkeys, to_block
