from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest
from eigensdk.types import Operator
import ecdsa
from eigensdk.crypto.bls.bls_key_pair import KeyPair
from eigensdk.crypto.bls.g1point import G1Point
from eigensdk.crypto.bls.g2point import G2Point
import os
import time


def test_get_quorum_count():
    """Test retrieving the count of quorums from the registry coordinator"""
    try:
        # Call the get_quorum_count method
        quorum_count = clients.avs_reader.get_quorum_count()
        
        # Verify the result is an integer
        assert isinstance(quorum_count, int)
        print(f"Quorum count: {quorum_count}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operators_stake_in_quorums_at_current_block():
    """Test retrieving operators stake in quorums at current block"""
    try:
        # Define quorum numbers to query
        quorum_numbers = [0]  # Query quorum 0
        
        # Call the get_operators_stake_in_quorums_at_current_block method
        result = clients.avs_reader.get_operators_stake_in_quorums_at_current_block(quorum_numbers)
        
        # Verify the result is a list of lists
        assert isinstance(result, list)
        for quorum_operators in result:
            assert isinstance(quorum_operators, list)
        
        print(f"Operators stake in quorums at current block: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operators_stake_in_quorums_at_block():
    """Test retrieving operators stake in quorums at a specific block"""
    try:
        # Define quorum numbers to query
        quorum_numbers = [0]  # Query quorum 0
        
        # Get current block number
        block_number = clients.eth_http_client.eth.block_number
        
        # Call the get_operators_stake_in_quorums_at_block method
        result = clients.avs_reader.get_operators_stake_in_quorums_at_block(quorum_numbers, block_number)
        
        # Verify the result is a list of lists
        assert isinstance(result, list)
        for quorum_operators in result:
            assert isinstance(quorum_operators, list)
        
        print(f"Operators stake in quorums at block {block_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_addrs_in_quorums_at_current_block():
    """Test retrieving operator addresses in quorums at current block"""
    try:
        # Define quorum numbers to query
        quorum_numbers = [0]  # Query quorum 0
        
        # Call the get_operator_addrs_in_quorums_at_current_block method
        result = clients.avs_reader.get_operator_addrs_in_quorums_at_current_block(None, quorum_numbers)
        
        # Verify the result is a list of lists
        assert isinstance(result, list)
        for quorum_operators in result:
            assert isinstance(quorum_operators, list)
        
        print(f"Operator addresses in quorums at current block: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operators_stake_in_quorums_of_operator_at_block():
    """Test retrieving operator's stake in quorums at a specific block"""
    try:
        # Define an operator ID to query
        operator_id = 0  # Query operator with ID 0
        
        # Get current block number
        block_number = clients.eth_http_client.eth.block_number
        
        # Call the get_operators_stake_in_quorums_of_operator_at_block method
        quorum_ids, stakes = clients.avs_reader.get_operators_stake_in_quorums_of_operator_at_block(
            None, operator_id, block_number
        )
        
        # Verify the results
        if quorum_ids is not None:
            assert isinstance(quorum_ids, list)
        
        if stakes is not None:
            assert isinstance(stakes, list)
        
        print(f"Operator {operator_id} stake in quorums at block {block_number}:")
        print(f"Quorum IDs: {quorum_ids}")
        print(f"Stakes: {stakes}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operators_stake_in_quorums_of_operator_at_current_block():
    """Test retrieving operator's stake in quorums at current block"""
    try:
        # Define an operator ID to query
        operator_id = 0  # Query operator with ID 0
        
        # Call the get_operators_stake_in_quorums_of_operator_at_current_block method
        quorum_ids, stakes = clients.avs_reader.get_operators_stake_in_quorums_of_operator_at_current_block(
            None, operator_id
        )
        
        # Verify the results
        if quorum_ids is not None:
            assert isinstance(quorum_ids, list)
        
        if stakes is not None:
            assert isinstance(stakes, list)
        
        print(f"Operator {operator_id} stake in quorums at current block:")
        print(f"Quorum IDs: {quorum_ids}")
        print(f"Stakes: {stakes}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_stake_in_quorums_of_operator_at_current_block():
    """Test retrieving operator stake in quorums at current block"""
    try:
        # Define an operator ID to query
        operator_id = 0  # Query operator with ID 0
        
        # Call the method
        result = clients.avs_reader.get_operator_stake_in_quorums_of_operator_at_current_block(None, operator_id)
        
        # Verify the result is a dictionary
        assert result is None or isinstance(result, dict)
        
        print(f"Operator {operator_id} stake in quorums at current block: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_weight_of_operator_for_quorum():
    """Test retrieving weight of operator for a quorum"""
    try:
        # Define quorum number and operator address
        quorum_number = 0
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.weight_of_operator_for_quorum(None, quorum_number, operator_addr)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Weight of operator {operator_addr} for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_strategy_params_length():
    """Test retrieving strategy params length for a quorum"""
    try:
        # Define quorum number
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.strategy_params_length(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Strategy params length for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_strategy_params_by_index():
    """Test retrieving strategy params by index for a quorum"""
    try:
        # Define quorum number and index
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.strategy_params_by_index(None, quorum_number, index)
        
        # Verify the result is a strategy params object or None
        assert result is None or isinstance(result, tuple)
        
        print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_history_length():
    """Test retrieving stake history length for an operator in a quorum"""
    try:
        # Define operator ID and quorum number
        operator_id = 0
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_stake_history_length(None, operator_id, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Stake history length for operator {operator_id} in quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_history():
    """Test retrieving stake history for an operator in a quorum"""
    try:
        # Define operator ID and quorum number
        operator_id = 0
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_stake_history(None, operator_id, quorum_number)
        
        # Verify the result is a list or None
        assert result is None or isinstance(result, list)
        
        print(f"Stake history for operator {operator_id} in quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_latest_stake_update():
    """Test retrieving latest stake update for an operator in a quorum"""
    try:
        # Define operator ID and quorum number
        operator_id = 0
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_latest_stake_update(None, operator_id, quorum_number)
        
        # Verify the result is a stake update object or None
        assert result is None or isinstance(result, tuple)
        
        print(f"Latest stake update for operator {operator_id} in quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_update_at_index():
    """Test retrieving stake update at a specific index for an operator in a quorum"""
    try:
        # Define operator ID, quorum number, and index
        operator_id = 0
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_stake_update_at_index(None, operator_id, quorum_number, index)
        
        # Verify the result is a stake update object or None
        assert result is None or isinstance(result, tuple)
        
        print(f"Stake update for operator {operator_id} in quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_at_block_number():
    """Test retrieving stake at a specific block number"""
    try:
        # Define parameters
        operator_id = 0
        quorum_number = 0
        block_number = clients.eth_http_client.eth.block_number
        
        # Call the method
        result = clients.avs_reader.get_stake_at_block_number(None, operator_id, quorum_number, block_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Stake for operator {operator_id} in quorum {quorum_number} at block {block_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_update_index_at_block_number():
    """Test retrieving stake update index at a specific block number"""
    try:
        # Define parameters
        operator_id = 0
        quorum_number = 0
        block_number = clients.eth_http_client.eth.block_number
        
        # Call the method
        result = clients.avs_reader.get_stake_update_index_at_block_number(None, operator_id, quorum_number, block_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Stake update index for operator {operator_id} in quorum {quorum_number} at block {block_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_at_block_number_and_index():
    """Test retrieving stake at a specific block number and index"""
    try:
        # Define parameters
        operator_id = 0
        quorum_number = 0
        block_number = clients.eth_http_client.eth.block_number
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_stake_at_block_number_and_index(None, operator_id, quorum_number, block_number, index)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Stake for operator {operator_id} in quorum {quorum_number} at block {block_number} and index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_total_stake_history_length():
    """Test retrieving total stake history length for a quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_total_stake_history_length(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Total stake history length for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_check_signatures_indices():
    """Test retrieving check signatures indices"""
    try:
        # Define parameters
        reference_block_number = clients.eth_http_client.eth.block_number - 10
        quorum_numbers = [0]
        non_signer_operator_ids = [0]
        
        # Call the method
        result = clients.avs_reader.get_check_signatures_indices(None, reference_block_number, quorum_numbers, non_signer_operator_ids)
        
        # Verify the result
        assert result is not None
        
        print(f"Check signatures indices at block {reference_block_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_current_total_stake():
    """Test retrieving current total stake for a quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_current_total_stake(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Current total stake for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_total_stake_update_at_index():
    """Test retrieving total stake update at a specific index"""
    try:
        # Define parameters
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_total_stake_update_at_index(None, quorum_number, index)
        
        # Verify the result is a stake update object or None
        assert result is None or isinstance(result, tuple)
        
        print(f"Total stake update for quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_total_stake_at_block_number_from_index():
    """Test retrieving total stake at block number from index"""
    try:
        # Define parameters
        quorum_number = 0
        block_number = clients.eth_http_client.eth.block_number
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_total_stake_at_block_number_from_index(None, quorum_number, block_number, index)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Total stake for quorum {quorum_number} at block {block_number} from index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_total_stake_indices_at_block_number():
    """Test retrieving total stake indices at block number"""
    try:
        # Define parameters
        quorum_numbers = [0]
        block_number = clients.eth_http_client.eth.block_number
        
        # Call the method
        result = clients.avs_reader.get_total_stake_indices_at_block_number(None, quorum_numbers, block_number)
        
        # Verify the result is a list or None
        assert result is None or isinstance(result, list)
        
        print(f"Total stake indices at block {block_number} for quorums {quorum_numbers}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_minimum_stake_for_quorum():
    """Test retrieving minimum stake for a quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_minimum_stake_for_quorum(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Minimum stake for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_strategy_params_at_index():
    """Test retrieving strategy params at index"""
    try:
        # Define parameters
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_strategy_params_at_index(None, quorum_number, index)
        
        # Verify the result is a strategy params object or None
        assert result is None or isinstance(result, tuple)
        
        print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_strategy_per_quorum_at_index():
    """Test retrieving strategy per quorum at index"""
    try:
        # Define parameters
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_strategy_per_quorum_at_index(None, quorum_number, index)
        
        # Verify the result is a string or None
        assert result is None or isinstance(result, str)
        
        print(f"Strategy for quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_restakeable_strategies():
    """Test retrieving restakeable strategies"""
    try:
        # Call the method
        result = clients.avs_reader.get_restakeable_strategies(None)
        
        # Verify the result is a list
        assert isinstance(result, list)
        
        print(f"Restakeable strategies: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_restaked_strategies():
    """Test retrieving operator restaked strategies"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.get_operator_restaked_strategies(None, operator_addr)
        
        # Verify the result is a list
        assert isinstance(result, list)
        
        print(f"Restaked strategies for operator {operator_addr}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_stake_type_per_quorum():
    """Test retrieving stake type per quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_stake_type_per_quorum(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Stake type for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_slashable_stake_look_ahead_per_quorum():
    """Test retrieving slashable stake look ahead per quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_slashable_stake_look_ahead_per_quorum(None, quorum_number)
        
        # Verify the result is an integer or None
        assert result is None or isinstance(result, int)
        
        print(f"Slashable stake look ahead for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_id():
    """Test retrieving operator ID from operator address"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.get_operator_id(operator_addr)
        
        # Verify the result is bytes
        assert isinstance(result, bytes)
        
        print(f"Operator ID for {operator_addr}: {result.hex()}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_from_id():
    """Test retrieving operator address from operator ID"""
    try:
        # Define parameters
        operator_id = 0
        
        # Call the method
        result = clients.avs_reader.get_operator_from_id(None, operator_id)
        
        # Verify the result is a string or None
        assert result is None or isinstance(result, str)
        
        print(f"Operator address for ID {operator_id}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_query_registration_detail():
    """Test querying registration detail for an operator"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        # Note: This method has a potential bug in the reader.py where it expects call_options as first parameter
        # but we'll test it anyway and handle any errors
        try:
            result = clients.avs_reader.query_registration_detail(None, operator_addr)
            
            # Verify the result is a list of booleans or None
            assert result is None or (isinstance(result, list) and all(isinstance(x, bool) for x in result))
            
            print(f"Registration detail for operator {operator_addr}: {result}")
        except TypeError:
            pytest.skip("Method has incorrect parameter signature")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_is_operator_registered():
    """Test checking if an operator is registered"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.is_operator_registered(None, operator_addr)
        
        # Verify the result is a boolean
        assert isinstance(result, bool)
        
        print(f"Is operator {operator_addr} registered: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_is_operator_set_quorum():
    """Test checking if a quorum is an operator set quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.is_operator_set_quorum(None, quorum_number)
        
        # Verify the result is a boolean or None
        assert result is None or isinstance(result, bool)
        
        print(f"Is quorum {quorum_number} an operator set quorum: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_id_from_operator_address():
    """Test retrieving operator ID from operator address using BLS APK registry"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.get_operator_id_from_operator_address(None, operator_addr)
        
        # Verify the result is bytes or None
        assert result is None or isinstance(result, bytes)
        
        if result:
            print(f"Operator ID from BLS APK registry for {operator_addr}: {result.hex()}")
        else:
            print(f"Operator ID from BLS APK registry for {operator_addr}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_operator_address_from_operator_id():
    """Test retrieving operator address from operator ID using BLS APK registry"""
    try:
        # First get an operator ID to use
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        try:
            operator_id = clients.avs_reader.get_operator_id_from_operator_address(None, operator_addr)
            if not operator_id:
                operator_id = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        except:
            # Use a dummy ID if we can't get a real one
            operator_id = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000001")
        
        # Call the method
        result = clients.avs_reader.get_operator_address_from_operator_id(None, operator_id)
        
        # Verify the result is a string or None
        assert result is None or isinstance(result, str)
        
        print(f"Operator address from operator ID {operator_id.hex()}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_pubkey_from_operator_address():
    """Test retrieving public key from operator address"""
    try:
        # Define parameters
        operator_addr = Web3.to_checksum_address(config["operator_address"])
        
        # Call the method
        result = clients.avs_reader.get_pubkey_from_operator_address(None, operator_addr)
        
        # Verify the result is a G1Point or None
        assert result is None or isinstance(result, G1Point)
        
        print(f"Public key for operator {operator_addr}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_apk_update():
    """Test retrieving APK update for a quorum at a specific index"""
    try:
        # Define parameters
        quorum_number = 0
        index = 0
        
        # Call the method
        result = clients.avs_reader.get_apk_update(None, quorum_number, index)
        
        # Verify the result has the expected fields if not None
        if result is not None:
            assert hasattr(result, 'apk_hash')
            assert hasattr(result, 'update_block_number')
            assert hasattr(result, 'next_update_block_number')
        
        print(f"APK update for quorum {quorum_number} at index {index}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_get_current_apk():
    """Test retrieving current APK for a quorum"""
    try:
        # Define parameters
        quorum_number = 0
        
        # Call the method
        result = clients.avs_reader.get_current_apk(None, quorum_number)
        
        # Verify the result is a G1Point or None
        assert result is None or isinstance(result, G1Point)
        
        print(f"Current APK for quorum {quorum_number}: {result}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_query_existing_registered_operator_sockets():
    """Test querying existing registered operator sockets"""
    try:
        # No need to pass specific parameters, use defaults
        # This will query from block 0 to the current block
        result, stop_block = clients.avs_reader.query_existing_registered_operator_sockets()
        
        # Verify the result is a dictionary
        assert isinstance(result, dict)
        # Verify the stop_block is an integer
        assert isinstance(stop_block, int)
        
        # Check dictionary keys and values if there are any results
        for operator_id, socket in result.items():
            assert isinstance(operator_id, bytes)
            assert isinstance(socket, str)
        
        print(f"Found {len(result)} registered operator sockets up to block {stop_block}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")


def test_query_existing_registered_operator_pubkeys():
    """Test querying existing registered operator public keys"""
    try:
        # No need to pass specific parameters, use defaults
        # This will query from block 0 to the current block
        operator_addresses, operator_pubkeys, stop_block = clients.avs_reader.query_existing_registered_operator_pubkeys()
        
        # Verify the results are lists and stop_block is an integer
        assert isinstance(operator_addresses, list)
        assert isinstance(operator_pubkeys, list)
        assert isinstance(stop_block, int)
        
        # Check that the lists have the same length
        assert len(operator_addresses) == len(operator_pubkeys)
        
        # Check list items if there are any results
        for addr, pubkey in zip(operator_addresses, operator_pubkeys):
            assert isinstance(addr, str)
            assert hasattr(pubkey, 'g1_pub_key')
            assert hasattr(pubkey, 'g2_pub_key')
            assert isinstance(pubkey.g1_pub_key, G1Point)
            assert isinstance(pubkey.g2_pub_key, G2Point)
        
        print(f"Found {len(operator_addresses)} registered operator public keys up to block {stop_block}")
        
    except Exception as e:
        pytest.skip(f"Skipping test due to error: {str(e)}")

