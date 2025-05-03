from dataclasses import dataclass
from typing import Dict, Any, List
from tests.builder import holesky_avs_registry_reader
from eth_typing import Address

# TxParams type for call_options
TxParams = Dict[str, Any]


# Define the StakeRegistryTypesStrategyParams class
@dataclass
class StakeRegistryTypesStrategyParams:
    strategy: str  # Strategy contract address
    multiplier: int  # Weight multiplier for this strategy


# Define the StakeRegistryTypesStakeUpdate class
@dataclass
class StakeRegistryTypesStakeUpdate:
    updateBlockNumber: int  # Block number when the update occurred
    stake: int  # The stake amount


# def test_is_operator_set_quorum():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample quorum number
#     quorum_number = 0  # Typically starts at 0

#     return holesky_avs_registry_reader.is_operator_set_quorum(
#         call_options=call_options,
#         quorum_number=quorum_number
#     )


# def test_get_slashable_stake_look_ahead_per_quorum():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample quorum number
#     quorum_number = 0  # Typically starts at 0

#     return holesky_avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
#         call_options=call_options,
#         quorum_number=quorum_number
#     )


# def test_get_stake_type_per_quorum():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample quorum number
#     quorum_number = 0  # Typically starts at 0

#     return holesky_avs_registry_reader.get_stake_type_per_quorum(
#         call_options=call_options,
#         quorum_number=quorum_number
#     )


# def test_get_strategy_params_at_index():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample parameters
#     quorum_number = 0  # Typically starts at 0
#     index = 0  # First strategy in the quorum

#     return holesky_avs_registry_reader.get_strategy_params_at_index(
#         call_options=call_options,
#         quorum_number=quorum_number,
#         index=index
#     )


def test_get_minimum_stake_for_quorum():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample quorum number
    quorum_number = 0  # Typically starts at 0

    return holesky_avs_registry_reader.get_minimum_stake_for_quorum(
        call_options=call_options, quorum_number=quorum_number
    )


def test_get_total_stake_indices_at_block_number():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_numbers = bytes([0, 1])  # Encode quorum numbers as bytes
    block_number = 12345678  # Sample block number

    return holesky_avs_registry_reader.get_total_stake_indices_at_block_number(
        call_options=call_options, quorum_numbers=quorum_numbers, block_number=block_number
    )


def test_get_total_stake_at_block_number_from_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    block_number = (
        holesky_avs_registry_reader.eth_client.eth.block_number
    )  # Use current block number
    index = 0  # Sample index

    # First check if there are any stake updates
    history_length = holesky_avs_registry_reader.get_total_stake_history_length(
        call_options=call_options, quorum_number=quorum_number
    )

    if history_length == 0:
        return "No stake history available"

    return holesky_avs_registry_reader.get_total_stake_at_block_number_from_index(
        call_options=call_options,
        quorum_number=quorum_number,
        block_number=block_number,
        index=index,
    )


def test_get_total_stake_update_at_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    index = 0  # Sample index

    return holesky_avs_registry_reader.get_stake_update_at_index(
        call_options=call_options, quorum_number=quorum_number, operator_id=operator_id, index=index
    )


def test_get_current_total_stake():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample quorum number
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    # First check if the quorum exists and is initialized
    try:
        minimum_stake = holesky_avs_registry_reader.get_minimum_stake_for_quorum(
            call_options=call_options, quorum_number=quorum_number
        )
        if minimum_stake == 0:
            return "Quorum not initialized"
    except Exception as e:
        return f"Error checking quorum: {str(e)}"

    return holesky_avs_registry_reader.get_current_total_stake(
        call_options=call_options, quorum_number=quorum_number
    )


def test_get_total_stake_history_length():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    return holesky_avs_registry_reader.get_stake_history_length(
        call_options=call_options, operator_id=operator_id, quorum_number=quorum_number
    )


def test_get_stake_at_block_number():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    block_number = 12345678  # Sample block number

    return holesky_avs_registry_reader.get_stake_at_block_number(
        call_options=call_options,
        operator_id=operator_id,
        quorum_number=quorum_number,
        block_number=block_number,
    )


def test_get_operator_stake_in_quorums_of_operator_at_current_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample operator ID - encode as bytes32
    operator_id = bytes([123] + [0] * 31)  # Pad to 32 bytes

    return holesky_avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options=call_options, operator_id=operator_id
    )


def test_weight_of_operator_for_quorum():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    operator_addr = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"  # Sample operator address

    return holesky_avs_registry_reader.weight_of_operator_for_quorum(
        call_options, quorum_number, operator_addr
    )


def test_strategy_params_length():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample quorum number
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    return holesky_avs_registry_reader.strategy_params_length(
        call_options=call_options, quorum_number=quorum_number
    )


def test_strategy_params_by_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    # First check the length of strategy params
    length = holesky_avs_registry_reader.strategy_params_length(
        call_options=call_options, quorum_number=quorum_number
    )

    if length == 0:
        return "No strategy params available"

    # Use the last index in the array
    index = length - 1

    return holesky_avs_registry_reader.strategy_params_by_index(
        call_options=call_options, quorum_number=quorum_number, index=index
    )


def test_get_stake_history():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    return holesky_avs_registry_reader.get_stake_history(
        call_options=call_options, operator_id=operator_id, quorum_number=quorum_number
    )


def test_get_latest_stake_update():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    quorum_number = 0  # Sample quorum number (typically starts at 0)

    return holesky_avs_registry_reader.get_latest_stake_update(
        call_options=call_options, operator_id=operator_id, quorum_number=quorum_number
    )


def test_get_stake_update_at_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    index = 0  # Sample index

    return holesky_avs_registry_reader.get_stake_update_at_index(
        call_options=call_options, quorum_number=quorum_number, operator_id=operator_id, index=index
    )


def test_get_stake_at_block_number_and_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    block_number = 12345678  # Sample block number
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    index = 0  # Sample index

    return holesky_avs_registry_reader.get_stake_at_block_number_and_index(
        call_options=call_options,
        quorum_number=quorum_number,
        block_number=block_number,
        operator_id=operator_id,
        index=index,
    )


def test_get_stake_update_index_at_block_number():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    operator_id = bytes([123] + [0] * 31)  # Encode operator ID as bytes32
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    block_number = 12345678  # Sample block number

    return holesky_avs_registry_reader.get_stake_update_index_at_block_number(
        call_options=call_options,
        operator_id=operator_id,
        quorum_number=quorum_number,
        block_number=block_number,
    )


def test_get_strategy_per_quorum_at_index():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample parameters
    quorum_number = 0  # Sample quorum number (typically starts at 0)
    index = 0  # Sample index

    return holesky_avs_registry_reader.get_strategy_per_quorum_at_index(
        call_options=call_options, quorum_number=quorum_number, index=index
    )
