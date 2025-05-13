from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest
from eigensdk._types import Operator
from eigensdk.crypto.bls.attestation import KeyPair, G1Point, G2Point
import os
import time


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
    print(f"Operators stake in quorums at block {block_number}: {result}")


def test_get_operator_addrs_in_quorums_at_current_block():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block(
        quorum_numbers
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
    print(f"Operator addresses in quorums at current block: {result}")


# TODO: fix this test, YOU NEED TO REGISISTER QUORUM FIRST

# def test_get_operators_stake_in_quorums_of_operator_at_block():
#     operator_id = [1]
#     block_number = clients.eth_http_client.eth.block_number
#     quorum_ids, stakes = clients.avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
#         operator_id, block_number
#     )
#     if quorum_ids is not None:
#         assert isinstance(quorum_ids, list)
#     if stakes is not None:
#         assert isinstance(stakes, list)
#     print(f"Operator {operator_id} stake in quorums at block {block_number}:")
#     print(f"Quorum IDs: {quorum_ids}")
#     print(f"Stakes: {stakes}")


# TODO: fix this test, YOU NEED TO REGISISTER QUORUM FIRST

# def test_get_operators_stake_in_quorums_of_operator_at_current_block():
#     operator_id = [1]
#     quorum_ids, stakes = (
#         clients.avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(
#             operator_id
#         )
#     )
#     if quorum_ids is not None:
#         assert isinstance(quorum_ids, list)
#     if stakes is not None:
#         assert isinstance(stakes, list)
#     print(f"Operator {operator_id} stake in quorums at current block:")
#     print(f"Quorum IDs: {quorum_ids}")
#     print(f"Stakes: {stakes}")


# TODO: fix this test, ABI Incompatible

# def test_get_operator_stake_in_quorums_of_operator_at_current_block():
#     operator_id = 0  # Query operator with ID 0
#     result = clients.avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
#         operator_id
#     )
#     assert result is None or isinstance(result, dict)
#     print(f"Operator {operator_id} stake in quorums at current block: {result}")


def test_weight_of_operator_for_quorum():
    quorum_number = 0
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.weight_of_operator_for_quorum(quorum_number, operator_addr)
    assert result is None or isinstance(result, int)
    print(f"Weight of operator {operator_addr} for quorum {quorum_number}: {result}")


def test_strategy_params_length():
    quorum_number = 0
    result = clients.avs_registry_reader.strategy_params_length(
        quorum_number
    )  # Verify the result is an integer or None
    assert result is None or isinstance(result, int)
    print(f"Strategy params length for quorum {quorum_number}: {result}")


def test_strategy_params_by_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.strategy_params_by_index(quorum_number, index)
    assert result is None or isinstance(result, tuple)
    print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_stake_history_length():
#     operator_id = 1
#     quorum_number = 1
#     result = clients.avs_registry_reader.get_stake_history_length(operator_id, quorum_number)
#     assert result is None or isinstance(result, int)
#     print(
#         f"Stake history length for operator {operator_id} in quorum {quorum_number}: {result}"
#     )


# TODO: fix this test, ABI Incompatible

# def test_get_stake_history():
#     operator_id = 0
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_stake_history(operator_id, quorum_number)
#     assert result is None or isinstance(result, list)
#     print(f"Stake history for operator {operator_id} in quorum {quorum_number}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_latest_stake_update():
#     operator_id = 0
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_latest_stake_update(operator_id, quorum_number)
#     assert result is None or isinstance(result, tuple)
#     print(f"Latest stake update for operator {operator_id} in quorum {quorum_number}: {result}")

# TODO: fix this test, ABI Incompatible

# def test_get_stake_update_at_index():
#     operator_id = 1
#     quorum_number = 1
#     index = 1
#     result = clients.avs_registry_reader.get_stake_update_at_index(
#         operator_id, quorum_number, index
#     )
#     assert result is None or isinstance(result, tuple)
#     print(
#         f"Stake update for operator {operator_id} in quorum {quorum_number} at index {index}: {result}"
#     )


# def test_get_stake_at_block_number():
#     operator_id = 0
#     quorum_number = 0
#     block_number = clients.eth_http_client.eth.block_number
#     result = clients.avs_registry_reader.get_stake_at_block_number(
#         operator_id, quorum_number, block_number
#     )
#     assert result is None or isinstance(result, int)
#     print(
#         f"Stake for operator {operator_id} in quorum {quorum_number} at block {block_number}: {result}"
#     )

# def test_get_stake_update_index_at_block_number():
#     operator_id = 0
#     quorum_number = 0
#     block_number = clients.eth_http_client.eth.block_number
#     result = clients.avs_registry_reader.get_stake_update_index_at_block_number(
#         operator_id, quorum_number, block_number
#     )
#     assert result is None or isinstance(result, int)
#     print(
#         f"Stake update index for operator {operator_id} in quorum {quorum_number} at block {block_number}: {result}"
#     )

# def test_get_stake_at_block_number_and_index():
#     operator_id = 0
#     quorum_number = 0
#     block_number = clients.eth_http_client.eth.block_number
#     index = 0
#     result = clients.avs_registry_reader.get_stake_at_block_number_and_index(
#         None, operator_id, quorum_number, block_number, index
#     )
#     assert result is None or isinstance(result, int)
#     print(
#         f"Stake for operator {operator_id} in quorum {quorum_number} at block {block_number} and index {index}: {result}"
#     )


# def test_get_total_stake_history_length():
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_total_stake_history_length(None, quorum_number)
#     assert result is None or isinstance(result, int)
#     print(f"Total stake history length for quorum {quorum_number}: {result}")


# def test_get_check_signatures_indices():
#     reference_block_number = clients.eth_http_client.eth.block_number - 10
#     quorum_numbers = [0]
#     non_signer_operator_ids = [0]
#     result = clients.avs_registry_reader.get_check_signatures_indices(
#         reference_block_number, quorum_numbers, non_signer_operator_ids
#     )
#     assert result is not None
#     print(f"Check signatures indices at block {reference_block_number}: {result}")

# def test_get_current_total_stake():
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_current_total_stake(None, quorum_number)
#     assert result is None or isinstance(result, int)
#     print(f"Current total stake for quorum {quorum_number}: {result}")

# def test_get_total_stake_update_at_index():
#     quorum_number = 0
#     index = 0
#     result = clients.avs_registry_reader.get_total_stake_update_at_index(quorum_number, index)
#     assert result is None or isinstance(result, tuple)
#     print(f"Total stake update for quorum {quorum_number} at index {index}: {result}")


def test_get_total_stake_at_block_number_from_index():
    quorum_number = 0
    block_number = clients.eth_http_client.eth.block_number
    index = 0
    result = clients.avs_registry_reader.get_total_stake_at_block_number_from_index(
        quorum_number, block_number, index
    )
    assert result is None or isinstance(result, int)
    print(
        f"Total stake for quorum {quorum_number} at block {block_number} from index {index}: {result}"
    )


# TODO: fix this test, ABI Incompatible

# def test_get_total_stake_indices_at_block_number():
#     quorum_numbers = [0]
#     block_number = clients.eth_http_client.eth.block_number
#     result = clients.avs_registry_reader.get_total_stake_indices_at_block_number(
#         quorum_numbers, block_number
#     )
#     assert result is None or isinstance(result, list)
#     print(f"Total stake indices at block {block_number} for quorums {quorum_numbers}: {result}")


def test_get_minimum_stake_for_quorum():
    quorum_number = 0
    result = clients.avs_registry_reader.get_minimum_stake_for_quorum(quorum_number)
    assert result is None or isinstance(result, int)
    print(f"Minimum stake for quorum {quorum_number}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_strategy_params_at_index():
#     quorum_number = 0
#     index = 0
#     result = clients.avs_registry_reader.get_strategy_params_at_index(quorum_number, index)
#     assert result is None or isinstance(result, tuple)
#     print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")


def test_get_strategy_per_quorum_at_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.get_strategy_per_quorum_at_index(quorum_number, index)
    assert result is None or isinstance(result, str)
    print(f"Strategy for quorum {quorum_number} at index {index}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_restakeable_strategies():
#     result = clients.avs_registry_reader.get_restakeable_strategies(None)
#     assert isinstance(result, list)
#     print(f"Restakeable strategies: {result}")


# def test_get_operator_restaked_strategies():
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     result = clients.avs_registry_reader.get_operator_restaked_strategies(None, operator_addr)
#     assert isinstance(result, list)
#     print(f"Restaked strategies for operator {operator_addr}: {result}")


# def test_get_stake_type_per_quorum():
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_stake_type_per_quorum(None, quorum_number)
#     assert result is None or isinstance(result, int)
#     print(f"Stake type for quorum {quorum_number}: {result}")


# def test_get_slashable_stake_look_ahead_per_quorum():
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(None, quorum_number)
#     assert result is None or isinstance(result, int)
#     print(f"Slashable stake look ahead for quorum {quorum_number}: {result}")


def test_get_operator_id():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.get_operator_id(operator_addr)
    assert isinstance(result, bytes)
    print(f"Operator ID for {operator_addr}: {result.hex()}")


# def test_get_operator_from_id():
#     operator_id = 1
#     result = clients.avs_registry_reader.get_operator_from_id(operator_id)
#     assert result is None or isinstance(result, str)
#     print(f"Operator address for ID {operator_id}: {result}")


# def test_query_registration_detail():
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     result = clients.avs_registry_reader.query_registration_detail(None, operator_addr)
#     assert result is None or (
#         isinstance(result, list) and all(isinstance(x, bool) for x in result)
#     )
#     print(f"Registration detail for operator {operator_addr}: {result}")


# def test_is_operator_registered():
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     result = clients.avs_registry_reader.is_operator_registered(None, operator_addr)
#     assert isinstance(result, bool)

#     print(f"Is operator {operator_addr} registered: {result}")


# def test_is_operator_set_quorum():
#     quorum_number = 0
#     result = clients.avs_registry_reader.is_operator_set_quorum(None, quorum_number)
#     assert result is None or isinstance(result, bool)
#     print(f"Is quorum {quorum_number} an operator set quorum: {result}")


# def test_get_operator_id_from_operator_address():
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     result = clients.avs_registry_reader.get_operator_id_from_operator_address(None, operator_addr)
#     assert result is None or isinstance(result, bytes)
#     if result:
#         print(f"Operator ID from BLS APK registry for {operator_addr}: {result.hex()}")
#     else:
#         print(f"Operator ID from BLS APK registry for {operator_addr}: {result}")


def test_get_operator_address_from_operator_id():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operator_id = clients.avs_registry_reader.get_operator_id_from_operator_address(operator_addr)
    result = clients.avs_registry_reader.get_operator_address_from_operator_id(operator_id)
    assert result is None or isinstance(result, str)
    print(f"Operator address from operator ID {operator_id.hex()}: {result}")


def test_get_pubkey_from_operator_address():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.get_pubkey_from_operator_address(operator_addr)
    assert result is None or isinstance(result, G1Point)
    print(f"Public key for operator {operator_addr}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_apk_update():
#     quorum_number = 1
#     index = 1
#     result = clients.avs_registry_reader.get_apk_update(quorum_number, index)
#     if result is not None:
#         assert hasattr(result, "apk_hash")
#         assert hasattr(result, "update_block_number")
#         assert hasattr(result, "next_update_block_number")

#     print(f"APK update for quorum {quorum_number} at index {index}: {result}")


# TODO: fix this test, ABI Incompatible

# def test_get_current_apk():
#     quorum_number = 0
#     result = clients.avs_registry_reader.get_current_apk(quorum_number)
#     assert result is None or isinstance(result, G1Point)
#     print(f"Current APK for quorum {quorum_number}: {result}")


def test_query_existing_registered_operator_sockets():
    result, stop_block = clients.avs_registry_reader.query_existing_registered_operator_sockets()
    assert isinstance(result, dict)
    assert isinstance(stop_block, int)
    for operator_id, socket in result.items():
        assert isinstance(operator_id, bytes)
        assert isinstance(socket, str)
    print(f"Found {len(result)} registered operator sockets up to block {stop_block}")


def test_query_existing_registered_operator_pubkeys():
    operator_addresses, operator_pubkeys, stop_block = (
        clients.avs_registry_reader.query_existing_registered_operator_pubkeys()
    )
    assert isinstance(operator_addresses, list)
    assert isinstance(operator_pubkeys, list)
    assert isinstance(stop_block, int)
    assert len(operator_addresses) == len(operator_pubkeys)
    for addr, pubkey in zip(operator_addresses, operator_pubkeys):
        assert isinstance(addr, str)
        assert hasattr(pubkey, "g1_pub_key")
        assert hasattr(pubkey, "g2_pub_key")
        assert isinstance(pubkey.g1_pub_key, G1Point)
        assert isinstance(pubkey.g2_pub_key, G2Point)
    print(
        f"Found {len(operator_addresses)} registered operator public keys up to block {stop_block}"
    )
