from dataclasses import dataclass
from typing import Dict, Any
from tests.builder import holesky_avs_registry_reader
from eth_typing import Address

def test_get_operators_stake_in_quorums_at_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample parameters
    quorum_numbers = bytes([0, 1])  # Encode quorum numbers as bytes
    block_number = 12345678
    
    return holesky_avs_registry_reader.get_operators_stake_in_quorums_at_block(
        call_options=call_options,
        quorum_numbers=quorum_numbers,
        block_number=block_number
    )



def test_get_operator_addrs_in_quorums_at_current_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample parameters
    quorum_numbers = bytes([0, 1])  # Encode quorum numbers as bytes
    
    stakes = holesky_avs_registry_reader.get_operator_addrs_in_quorums_at_current_block(
        call_options=call_options,
        quorum_numbers=quorum_numbers
    )
    
    return stakes



def test_get_operators_stake_in_quorums_of_operator_at_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample parameters
    operator_id = bytes([123])  # Encode operator ID as bytes
    block_number = 12345678  # Sample block number
    
    return holesky_avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        call_options=call_options,
        operator_id=operator_id,
        block_number=block_number
    )


def test_get_operators_stake_in_quorums_of_operator_at_current_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample operator ID
    operator_id = bytes([123])  # Encode operator ID as bytes
    
    return holesky_avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(
        call_options=call_options,
        operator_id=operator_id
    )

