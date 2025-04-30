from dataclasses import dataclass
from typing import Dict, Any, List
from tests.builder import holesky_avs_registry_reader
from eth_typing import Address

# Constants
DEFAULT_QUERY_BLOCK_RANGE = 1000  # Default block range for event log queries

def test_get_quorum_count():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    return holesky_avs_registry_reader.get_quorum_count(
        call_options=call_options
    )



def test_get_operator_stake_in_quorums_of_operator_at_current_block():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample operator ID - encode as bytes32
    operator_id = bytes([123] + [0] * 31)  # Pad to 32 bytes
    
    return holesky_avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options=call_options,
        operator_id=operator_id
    )



def test_get_operator_id():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    
    return holesky_avs_registry_reader.get_operator_id(
        call_options=call_options,
        operator_address=operator_address
    )


def test_get_operator_from_id():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample operator ID - encode as bytes32
    operator_id = bytes([123] + [0] * 31)  # Pad to 32 bytes
    
    return holesky_avs_registry_reader.get_operator_from_id(
        call_options=call_options,
        operator_id=operator_id
    )



def test_is_operator_registered():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}
    
    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    
    return holesky_avs_registry_reader.is_operator_registered(
        call_options=call_options,
        operator_address=operator_address
    )



# def test_query_existing_registered_operator_sockets():
#     # Sample parameters
#     start_block = 12345000  # Sample start block number
#     stop_block = 12346000   # Sample stop block number
#     block_range = 500       # Sample block range (smaller than default for testing)
    
#     # Get the event topic
#     event = holesky_avs_registry_reader.registry_coordinator.events.OperatorSocketUpdate
#     event_topic = event.build_filter().topics[0]
    
#     # Get the logs with proper filter options
#     filter_opts = {
#         "fromBlock": start_block,
#         "toBlock": stop_block,
#         "topics": [event_topic]
#     }
    
#     logs = event.get_logs(filter_opts)
    
#     # Process the logs
#     result = {}
#     for log in logs:
#         args = log['args']
#         operator_id_raw = args.get('operatorId')
#         operator_id = bytes.fromhex(
#             operator_id_raw[2:] if operator_id_raw.startswith('0x') else operator_id_raw
#         )
#         result[operator_id] = str(args.get('socket', ''))
    
#     return result



# Utility function to convert bitmap to quorum IDs
def bitmap_to_quorum_ids(bitmap: int) -> List[int]:
    quorum_ids = []
    for i in range(256):  # Assuming maximum 256 quorums
        if bitmap & (1 << i):
            quorum_ids.append(i)
    return quorum_ids
