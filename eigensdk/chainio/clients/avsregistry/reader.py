import logging
from typing import Optional

from eth_typing import Address
from eth_utils import event_abi_to_log_topic
from web3 import Web3
from web3._utils.events import get_event_data
from web3.contract.contract import Contract

from eigensdk.chainio import utils
from eigensdk.chainio.utils import bitmap_to_quorum_ids
from eigensdk.crypto.bls.attestation import G1Point, G2Point
from eigensdk.types_ import (
    OperatorPubkeys,
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
)
from eigensdk.types_ import (
    StakeRegistryTypesStrategyParams,
    StakeRegistryTypesStakeUpdate,
    BLSApkRegistryTypesApkUpdate,
)

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

    def get_quorum_count(self) -> int:
        return self.registry_coordinator.functions.quorumCount().call()

    def get_operators_stake_in_quorums_at_current_block(
        self, quorum_numbers: list[int]
    ) -> list[list[OperatorStateRetrieverOperator]]:
        cur_block = self.eth_http_client.eth.block_number
        return self.get_operators_stake_in_quorums_at_block(quorum_numbers, cur_block)

    def get_operators_stake_in_quorums_at_block(
        self, quorum_numbers: list[int], block_number: int
    ) -> list[list[OperatorStateRetrieverOperator]]:
        operator_stakes = self.operator_state_retriever.get_function_by_signature(
            "getOperatorState(address,bytes,uint32)"
        )(
            registryCoordinator=self.registry_coordinator_addr,
            quorumNumbers=utils.nums_to_bytes(quorum_numbers),
            blockNumber=block_number,
        ).call()
        return [
            [
                OperatorStateRetrieverOperator(
                    operator=operator[0],
                    operator_id=operator[1],
                    stake=operator[2],
                )
                for operator in quorum
            ]
            for quorum in operator_stakes
        ]

    def get_operator_addrs_in_quorums_at_current_block(
        self, quorum_numbers: list[int]
    ) -> list[list[str]]:
        cur_block = self.eth_http_client.eth.block_number
        stakes = self.get_operators_stake_in_quorums_at_block(quorum_numbers, cur_block)
        return [[op.operator for op in quorum] for quorum in stakes]

    def get_operators_stake_in_quorums_of_operator_at_block(
        self, operator_id: bytes, block_number: int
    ) -> tuple[list[int], list[list[OperatorStateRetrieverOperator]]]:
        quorum_bitmap, operator_stakes = self.operator_state_retriever.get_function_by_signature(
            "getOperatorState(address,bytes32,uint32)"
        )(self.registry_coordinator_addr, operator_id, block_number).call()

        # Convert the bitmap to quorum IDs
        quorums = bitmap_to_quorum_ids(quorum_bitmap)
        return quorums, [
            [
                OperatorStateRetrieverOperator(
                    operator=operator[0],
                    operator_id=operator[1],
                    stake=operator[2],
                )
                for operator in quorum
            ]
            for quorum in operator_stakes
        ]

    def get_operators_stake_in_quorums_of_operator_at_current_block(
        self, operator_id: bytes
    ) -> tuple[list[int], list[list[OperatorStateRetrieverOperator]]]:
        cur_block = self.eth_http_client.eth.block_number
        return self.get_operators_stake_in_quorums_of_operator_at_block(operator_id, cur_block)

    def weight_of_operator_for_quorum(self, quorum_number: int, operator_addr: str) -> int:
        return self.stake_registry.functions.weightOfOperatorForQuorum(
            quorum_number, operator_addr
        ).call()

    def strategy_params_length(self, quorum_number: int) -> int:
        return self.stake_registry.functions.strategyParamsLength(quorum_number).call()

    def strategy_params_by_index(
        self, quorum_number: int, index: int
    ) -> StakeRegistryTypesStrategyParams:
        result = self.stake_registry.functions.strategyParamsByIndex(quorum_number, index).call()
        return StakeRegistryTypesStrategyParams(strategy=result[0], multiplier=result[1])

    def get_stake_history_length(self, operator_id: bytes, quorum_number: int) -> int:
        return self.stake_registry.functions.getStakeHistoryLength(
            operator_id, quorum_number
        ).call()

    def get_stake_history(
        self, operator_id: bytes, quorum_number: int
    ) -> Optional[list[StakeRegistryTypesStakeUpdate]]:
        return self.stake_registry.functions.getStakeHistory(operator_id, quorum_number).call()

    def get_latest_stake_update(
        self, operator_id: bytes, quorum_number: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getLatestStakeUpdate(operator_id, quorum_number).call()

    def get_stake_update_at_index(
        self, operator_id: bytes, quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getStakeUpdateAtIndex(
            quorum_number, operator_id, index
        ).call()

    def get_stake_at_block_number(
        self,
        operator_id: bytes,
        quorum_number: int,
        block_number: int,
    ) -> Optional[int]:
        return self.stake_registry.functions.getStakeAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call()

    def get_stake_update_index_at_block_number(
        self,
        operator_id: bytes,
        quorum_number: int,
        block_number: int,
    ) -> int:
        return self.stake_registry.functions.getStakeUpdateIndexAtBlockNumber(
            operator_id, quorum_number, block_number
        ).call()

    def get_total_stake_history_length(self, quorum_number: int) -> int:
        return self.stake_registry.functions.getTotalStakeHistoryLength(quorum_number).call()

    def get_check_signatures_indices(
        self,
        reference_block_number: int,
        quorum_numbers: list[int],
        non_signer_operator_ids: list[bytes],
    ) -> OperatorStateRetrieverCheckSignaturesIndices:
        quorum_bytes = utils.nums_to_bytes(quorum_numbers)
        result = self.operator_state_retriever.functions.getCheckSignaturesIndices(
            self.registry_coordinator_addr,
            reference_block_number,
            quorum_bytes,
            non_signer_operator_ids,
        ).call()

        return OperatorStateRetrieverCheckSignaturesIndices(
            result[0], result[1], result[2], result[3]
        )

    def get_current_total_stake(self, quorum_number: int) -> int:
        return self.stake_registry.functions.getCurrentTotalStake(quorum_number).call()

    def get_total_stake_update_at_index(
        self, quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStakeUpdate]:
        return self.stake_registry.functions.getTotalStakeUpdateAtIndex(quorum_number, index).call()

    def get_total_stake_at_block_number_from_index(
        self, quorum_number: int, block_number: int, index: int
    ) -> Optional[int]:
        return self.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex(
            quorum_number, block_number, index
        ).call()

    def get_total_stake_indices_at_block_number(
        self, quorum_numbers: list[int], block_number: int
    ) -> Optional[list[int]]:
        quorum_bytes = utils.nums_to_bytes(quorum_numbers)  # Convert list[int] → bytes
        return self.stake_registry.functions.getTotalStakeIndicesAtBlockNumber(
            block_number, quorum_bytes
        ).call()

    def get_minimum_stake_for_quorum(self, quorum_number: int) -> Optional[int]:
        return self.stake_registry.functions.minimumStakeForQuorum(quorum_number).call()

    def get_strategy_params_at_index(
        self, quorum_number: int, index: int
    ) -> Optional[StakeRegistryTypesStrategyParams]:
        return self.stake_registry.functions.strategyParams(quorum_number, index).call()

    def get_strategy_per_quorum_at_index(self, quorum_number: int, index: int) -> Optional[str]:
        return self.stake_registry.functions.strategiesPerQuorum(quorum_number, index).call()

    # TODO: IMPLEMENT TEST BASED ON THE AVS SERVICE MANAGER
    def get_restakeable_strategies(self) -> list[str]:
        return self.service_manager.functions.getRestakeableStrategies().call()

    # TODO: IMPLEMENT TEST BASED ON THE AVS SERVICE MANAGER
    def get_operator_restaked_strategies(self, operator: str) -> list[str]:
        return self.service_manager.functions.getOperatorRestakedStrategies(operator).call()

    def get_stake_type_per_quorum(self, quorum_number: int) -> Optional[int]:
        return self.stake_registry.functions.stakeTypePerQuorum(quorum_number).call()

    def get_slashable_stake_look_ahead_per_quorum(self, quorum_number: int) -> Optional[int]:
        return self.stake_registry.functions.slashableStakeLookAheadPerQuorum(quorum_number).call()

    def get_operator_id(self, operator_address: Address) -> bytes:
        operator_id = self.registry_coordinator.functions.getOperatorId(operator_address).call()
        return operator_id

    def get_operator_from_id(self, operator_id: bytes) -> Optional[str]:
        return self.registry_coordinator.functions.getOperatorFromId(operator_id).call()

    def query_registration_detail(self, operator_address: Address) -> Optional[list[bool]]:
        operator_id = self.get_operator_id(operator_address=operator_address)
        value = self.registry_coordinator.functions.getCurrentQuorumBitmap(operator_id).call()
        return [(value & (1 << i)) != 0 for i in range(value.bit_length())]

    def is_operator_registered(self, operator_address: str) -> bool:
        return self.registry_coordinator.functions.getOperatorStatus(operator_address).call() == 1

    def is_operator_set_quorum(self, quorum_number: int) -> Optional[bool]:
        return self.stake_registry.functions.isOperatorSetQuorum(quorum_number).call()

    def get_operator_id_from_operator_address(self, operator_address: str) -> Optional[bytes]:
        return self.bls_apk_registry.functions.operatorToPubkeyHash(operator_address).call()

    def get_operator_address_from_operator_id(self, operator_pubkey_hash: bytes) -> Optional[str]:
        return self.bls_apk_registry.functions.pubkeyHashToOperator(operator_pubkey_hash).call()

    def get_pubkey_from_operator_address(self, operator_address: str) -> Optional[G1Point]:
        operator_pubkey = self.bls_apk_registry.functions.operatorToPubkey(operator_address).call()
        return G1Point(operator_pubkey[0], operator_pubkey[1])

    def get_apk_update(self, quorum_number: int, index: int) -> BLSApkRegistryTypesApkUpdate:
        update = self.bls_apk_registry.functions.apkHistory(quorum_number, index).call()
        return BLSApkRegistryTypesApkUpdate(
            apk_hash=bytes(update[0]),  # or update["apkHash"]
            update_block_number=update[1],  # or update["updateBlockNumber"]
            next_update_block_number=update[2],  # or update["nextUpdateBlockNumber"]
        )

    def get_current_apk(self, quorum_number: int) -> G1Point:
        apk = self.bls_apk_registry.functions.currentApk(quorum_number).call()
        return G1Point(x=apk[0], y=apk[1])  # Use index-based access

    def query_existing_registered_operator_sockets(
        self,
        start_block: int = 0,
        stop_block: Optional[int] = None,
        block_range: int = DEFAULT_QUERY_BLOCK_RANGE,
    ) -> tuple[dict[bytes, str], int]:
        if stop_block is None:
            stop_block = self.eth_http_client.eth.block_number

        operator_id_to_socket_map: dict[bytes, str] = {}

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
                operator_id = log["args"]["operatorId"]
                socket = log["args"]["socket"]

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
    ) -> tuple[list[Address], list[OperatorPubkeys]]:
        if stop_block is None:
            stop_block = self.eth_http_client.eth.block_number

        operator_pubkeys: list[OperatorPubkeys] = []
        operator_addresses: list[Address] = []
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
                    "from_block": i,
                    "to_block": to_block,
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
        return operator_addresses, operator_pubkeys

    def get_registry_coordinator_owner(self) -> str:
        return self.registry_coordinator.functions.owner().call()

    def is_registry_coordinator_owner(self, address: str) -> bool:
        owner = self.get_registry_coordinator_owner()
        return owner.lower() == address.lower()

    def can_satisfy_only_coordinator_owner_modifier(self, address: str) -> bool:
        return self.is_registry_coordinator_owner(address)
