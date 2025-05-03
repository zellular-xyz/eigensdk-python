from dataclasses import dataclass
from typing import Dict, Any
from tests.builder import holesky_avs_registry_reader
from eth_typing import Address

# TxParams type for call_options
TxParams = Dict[str, Any]


# Define the BLSApkRegistryTypesApkUpdate class
@dataclass
class BLSApkRegistryTypesApkUpdate:
    apk_hash: bytes
    update_block_number: int
    next_update_block_number: int


def test_get_operator_id_from_operator_address():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"

    return holesky_avs_registry_reader.get_operator_id_from_operator_address(
        call_options=call_options, operator_address=operator_address
    )


def test_get_operator_address_from_operator_id():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample operator pubkey hash (32 bytes of zeros as an example)
    operator_pubkey_hash = b"\x00" * 32

    return holesky_avs_registry_reader.get_operator_address_from_operator_id(
        call_options=call_options, operator_pubkey_hash=operator_pubkey_hash
    )


def test_get_pubkey_from_operator_address():
    # Sample call options (empty dictionary is fine for most calls)
    call_options = {}

    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"

    return holesky_avs_registry_reader.get_pubkey_from_operator_address(
        call_options=call_options, operator_address=operator_address
    )


# def test_get_apk_update():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample parameters
#     quorum_number = 0  # Typically starts at 0
#     index = 0          # Get the first update

#     return holesky_avs_registry_reader.get_apk_update(
#         call_options=call_options,
#         quorum_number=quorum_number,
#         index=index
#     )


# def test_get_current_apk():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample quorum number
#     quorum_number = 0  # Typically starts at 0

#     return holesky_avs_registry_reader.get_current_apk(
#         call_options=call_options,
#         quorum_number=quorum_number
#     )
