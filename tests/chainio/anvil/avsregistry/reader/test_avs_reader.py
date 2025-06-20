import pytest
from web3 import Web3
from web3.exceptions import ContractLogicError
from typing import cast
from eth_typing import Address

from eigensdk.crypto.bls.attestation import G1Point, G2Point
from tests.builder import clients, config

from eigensdk.types_ import (
    OperatorPubkeys,
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
    StakeRegistryTypesStrategyParams,
    StakeRegistryTypesStakeUpdate,
    BLSApkRegistryTypesApkUpdate,
)


@pytest.fixture(scope="session")
def operator_id():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
        quorum_numbers
    )
    return result[0][0].operator_id


def test_get_quorum_count():
    quorum_count = clients.avs_registry_reader.get_quorum_count()
    assert isinstance(quorum_count, int)
    print(f"Quorum count: {quorum_count}")


def test_get_operators_stake_in_quorums_at_current_block():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
        quorum_numbers
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
        assert all(
            isinstance(operator, OperatorStateRetrieverOperator) for operator in quorum_operators
        )

    print(f"Operators stake in quorums at current block: {result}")


def test_get_operators_stake_in_quorums_at_block():
    quorum_numbers = [0]
    block_number = clients.eth_http_client.eth.block_number
    result = clients.avs_registry_reader.get_operators_stake_in_quorums_at_block(
        quorum_numbers, block_number
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
        assert all(
            isinstance(operator, OperatorStateRetrieverOperator) for operator in quorum_operators
        )

    print(f"Operators stake in quorums at block {block_number}: {result}")


def test_get_operator_addrs_in_quorums_at_current_block():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block(
        quorum_numbers
    )
    assert isinstance(result, list)
    for addresses in result:
        assert isinstance(addresses, list)
        assert all(isinstance(address, str) for address in addresses)
    print(f"Operator addresses in quorums at current block: {result}")


def test_get_operators_stake_in_quorums_of_operator_at_block(operator_id):
    block_number = clients.eth_http_client.eth.block_number

    result = clients.avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        operator_id, block_number
    )
    print(f"Result: {result}")
    assert isinstance(result, tuple) and len(result) == 2
    quorum_ids_result, stakes_result = result

    assert isinstance(quorum_ids_result, list)
    assert all(isinstance(qid, int) for qid in quorum_ids_result)

    assert isinstance(stakes_result, list)
    assert all(isinstance(s, list) for s in stakes_result)
    for stake_list in stakes_result:
        assert all(isinstance(operator, OperatorStateRetrieverOperator) for operator in stake_list)

    print(f"Operator ID: {operator_id} → Quorum IDs: {quorum_ids_result}")
    print(f"Stakes at block {block_number}: {stakes_result}")


def test_weight_of_operator_for_quorum():
    quorum_number = 0
    operator_addr = Web3.to_checksum_address(config["operator_address_1"])
    result = clients.avs_registry_reader.weight_of_operator_for_quorum(quorum_number, operator_addr)
    assert isinstance(result, int)
    print(f"Weight of operator {operator_addr} for quorum {quorum_number}: {result}")


def test_strategy_params_length():
    quorum_number = 0
    result = clients.avs_registry_reader.strategy_params_length(quorum_number)
    assert isinstance(result, int)
    print(f"Strategy params length for quorum {quorum_number}: {result}")


def test_strategy_params_by_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.strategy_params_by_index(quorum_number, index)
    assert isinstance(result, StakeRegistryTypesStrategyParams)
    print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")


def test_get_stake_history_length(operator_id):
    quorum_number = 0
    stake_history_length = clients.avs_registry_reader.get_stake_history_length(
        operator_id, quorum_number
    )
    assert isinstance(stake_history_length, int)
    assert stake_history_length >= 0
    print(
        f"Stake history length for operator {operator_id} in quorum {quorum_number}: {stake_history_length}"
    )


def test_get_stake_history(operator_id):
    quorum_number = 0

    stake_history = clients.avs_registry_reader.get_stake_history(operator_id, quorum_number)

    assert isinstance(stake_history, list)
    assert all(isinstance(update, StakeRegistryTypesStakeUpdate) for update in stake_history)

    print(f"Stake history for operator {operator_id} in quorum {quorum_number}: {stake_history}")


def test_get_latest_stake_update(operator_id):
    quorum_number = 0
    latest_update = clients.avs_registry_reader.get_latest_stake_update(operator_id, quorum_number)
    assert isinstance(latest_update, StakeRegistryTypesStakeUpdate)

    print(
        f"Last stake update for operator {operator_id} in quorum {quorum_number}: {latest_update}"
    )


def test_get_stake_update_at_index(operator_id):
    quorum_number = 0
    history_length = clients.avs_registry_reader.get_stake_history_length(
        operator_id, quorum_number
    )
    assert isinstance(history_length, int)
    assert history_length > 0

    index = history_length - 1
    stake_update = clients.avs_registry_reader.get_stake_update_at_index(
        operator_id, quorum_number, index
    )
    assert isinstance(stake_update, StakeRegistryTypesStakeUpdate)
    print(
        f"Stake update at index {index} for operator {operator_id} in quorum {quorum_number}: {stake_update}"
    )


def test_get_stake_at_block_number(operator_id):
    quorum_number = 0
    block_number = clients.eth_http_client.eth.block_number

    stake = clients.avs_registry_reader.get_stake_at_block_number(
        operator_id, quorum_number, block_number
    )

    assert isinstance(stake, int)
    assert stake >= 0

    print(
        f"Stake at block {block_number} for operator {operator_id} in quorum {quorum_number}: {stake}"
    )


def test_get_stake_update_index_at_block_number(operator_id):
    quorum_number = 0
    block_number = clients.eth_http_client.eth.block_number

    index = clients.avs_registry_reader.get_stake_update_index_at_block_number(
        operator_id, quorum_number, block_number
    )

    assert isinstance(index, int)
    assert index >= 0

    print(
        f"Stake update index for operator {operator_id} in quorum {quorum_number} at block {block_number}: {index}"
    )


def test_get_total_stake_history_length():
    quorum_number = 0

    total_length = clients.avs_registry_reader.get_total_stake_history_length(quorum_number)

    assert isinstance(total_length, int)
    assert total_length >= 0

    print(f"Total stake history length for quorum {quorum_number}: {total_length}")


def test_get_check_signatures_indices(operator_id):
    reference_block_number = clients.eth_http_client.eth.block_number - 1
    quorum_numbers = [0]
    non_signer_operator_ids = [operator_id]

    result = clients.avs_registry_reader.get_check_signatures_indices(
        reference_block_number, quorum_numbers, non_signer_operator_ids
    )

    assert isinstance(result, OperatorStateRetrieverCheckSignaturesIndices)
    print(f"Check Signatures Indices result at block {reference_block_number}: {result}")


def test_get_current_total_stake():
    quorum_number = 0
    total_stake = clients.avs_registry_reader.get_current_total_stake(quorum_number)
    assert isinstance(total_stake, int)
    assert total_stake >= 0
    print(f"Current total stake for quorum {quorum_number}: {total_stake}")


def test_get_total_stake_update_at_index():
    quorum_number = 0
    total_length = clients.avs_registry_reader.get_total_stake_history_length(quorum_number)
    assert isinstance(total_length, int) and total_length > 0
    index = total_length - 1
    update = clients.avs_registry_reader.get_total_stake_update_at_index(quorum_number, index)
    assert isinstance(update, StakeRegistryTypesStakeUpdate)
    print(f"Total stake update for quorum {quorum_number} at index {index}: {update}")


def test_get_total_stake_at_block_number_from_index():
    quorum_number = 0
    block_number = clients.eth_http_client.eth.block_number
    index = 0
    result = clients.avs_registry_reader.get_total_stake_at_block_number_from_index(
        quorum_number, block_number, index
    )
    assert isinstance(result, int)
    print(
        f"Total stake for quorum {quorum_number} at block {block_number} from index {index}: {result}"
    )


def test_get_total_stake_indices_at_block_number():
    quorum_numbers = [0]
    block_number = clients.eth_http_client.eth.block_number

    indices = clients.avs_registry_reader.get_total_stake_indices_at_block_number(
        quorum_numbers, block_number
    )

    assert isinstance(indices, list)
    assert all(isinstance(i, int) for i in indices)

    print(f"Total stake indices at block {block_number} for quorums {quorum_numbers}: {indices}")


def test_get_minimum_stake_for_quorum():
    quorum_number = 0
    result = clients.avs_registry_reader.get_minimum_stake_for_quorum(quorum_number)
    assert isinstance(result, int)
    print(f"Minimum stake for quorum {quorum_number}: {result}")


def test_get_strategy_params_at_index():
    quorum_number = 0
    total_stake_strategy_count = clients.avs_registry_reader.get_total_stake_history_length(
        quorum_number
    )
    assert total_stake_strategy_count is not None and (
        total_stake_strategy_count >= 1
    ), f"No strategy parameters found for quorum {quorum_number}"
    index = total_stake_strategy_count - 1
    strategy_param = clients.avs_registry_reader.get_strategy_params_at_index(quorum_number, index)
    assert strategy_param is not None


def test_get_strategy_per_quorum_at_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.get_strategy_per_quorum_at_index(quorum_number, index)
    assert isinstance(result, str)
    print(f"Strategy for quorum {quorum_number} at index {index}: {result}")


def test_get_stake_type_per_quorum():
    quorum_number = 0
    stake_type = clients.avs_registry_reader.get_stake_type_per_quorum(quorum_number)
    assert isinstance(stake_type, int), "Stake type should be an integer"
    assert 0 <= stake_type <= 255, "Stake type should fit within uint8 range"
    print(f"Stake type for quorum {quorum_number}: {stake_type}")


def test_get_slashable_stake_look_ahead_per_quorum():
    quorum_number = 0
    lookahead = clients.avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(quorum_number)
    assert isinstance(lookahead, int), "Lookahead value should be an integer"
    assert lookahead >= 0, "Lookahead should be non-negative"
    print(f"Slashable stake lookahead for quorum {quorum_number}: {lookahead}")


def test_get_operator_id():
    operator_addr = Web3.to_checksum_address(config["operator_address_1"])
    result = clients.avs_registry_reader.get_operator_id(cast(Address, operator_addr))
    assert isinstance(result, bytes)
    print(f"Operator ID for {operator_addr}: {result.hex()}")


def test_get_operator_from_id(operator_id):
    address = clients.avs_registry_reader.get_operator_from_id(operator_id)
    assert address is not None, "Returned address should not be None"
    assert Web3.is_checksum_address(address), f"Invalid Ethereum address returned: {address}"
    print(f"Operator ID {operator_id} maps to address: {address}")


def test_query_registration_detail():
    operator = Web3.to_checksum_address(config["operator_address_1"])
    result = clients.avs_registry_reader.query_registration_detail(cast(Address, operator))

    assert isinstance(result, list)
    assert all(isinstance(x, bool) for x in result)

    print(f"Quorum participation bitmap for operator {operator}: {result}")


def test_get_operator_address_from_operator_id(operator_id):
    result = clients.avs_registry_reader.get_operator_address_from_operator_id(operator_id)
    assert isinstance(result, str)
    print(f"Operator address from operator ID {operator_id.hex()}: {result}")


def test_get_pubkey_from_operator_address():
    operator_addr = Web3.to_checksum_address(config["operator_address_1"])
    result = clients.avs_registry_reader.get_pubkey_from_operator_address(operator_addr)
    assert isinstance(result, G1Point)
    print(f"Public key for operator {operator_addr}: {result}")


def test_get_apk_update():
    quorum_number = 0
    index = 0
    update = clients.avs_registry_reader.get_apk_update(quorum_number, index)
    assert update is not None, "APK update should not be None"
    assert isinstance(update.apk_hash, bytes)
    assert isinstance(update.update_block_number, int)
    assert isinstance(update.next_update_block_number, int)
    print(f"APK Update for quorum {quorum_number}, index {index}:")
    print(f"  Hash: {update.apk_hash.hex()}")
    print(f"  Update Block: {update.update_block_number}")
    print(f"  Next Update Block: {update.next_update_block_number}")


def test_get_current_apk():
    quorum_number = 0
    apk = clients.avs_registry_reader.get_current_apk(quorum_number)
    assert apk is not None, "APK should not be None"
    print(f"Current APK for quorum {quorum_number}:")
    print(f"  x = {apk.x}")
    print(f"  y = {apk.y}")


def test_query_existing_registered_operator_sockets():
    result, stop_block = clients.avs_registry_reader.query_existing_registered_operator_sockets()
    assert isinstance(result, dict)
    assert isinstance(stop_block, int)
    for operator_id, socket in result.items():
        assert isinstance(operator_id, bytes)
        assert isinstance(socket, str)
    print(f"Found {len(result)} registered operator sockets up to block {stop_block}")


def test_query_existing_registered_operator_pubkeys():
    operator_addresses, operator_pubkeys = (
        clients.avs_registry_reader.query_existing_registered_operator_pubkeys()
    )
    assert isinstance(operator_addresses, list)
    assert isinstance(operator_pubkeys, list)
    assert len(operator_addresses) == len(operator_pubkeys)
    for addr, pubkey in zip(operator_addresses, operator_pubkeys):
        assert isinstance(addr, str)
        assert hasattr(pubkey, "g1_pub_key")
        assert hasattr(pubkey, "g2_pub_key")
        assert isinstance(pubkey.g1_pub_key, G1Point)
        assert isinstance(pubkey.g2_pub_key, G2Point)
    print(f"Found {len(operator_addresses)} registered operator public keys")


def test_registry_coordinator_owner():
    owner = clients.avs_registry_reader.get_registry_coordinator_owner()
    assert Web3.is_address(owner), "Owner should be a valid Ethereum address"
    print(f"RegistryCoordinator owner: {owner}")
    is_owner = clients.avs_registry_reader.is_registry_coordinator_owner(owner)
    assert is_owner is True, "Owner should be verified as the owner"
    test_address = Web3.to_checksum_address("0x1234567890123456789012345678901234567890")
    can_satisfy = clients.avs_registry_reader.can_satisfy_only_coordinator_owner_modifier(
        test_address
    )
    print(f"Can address {test_address} satisfy onlyCoordinatorOwner modifier? {can_satisfy}")
