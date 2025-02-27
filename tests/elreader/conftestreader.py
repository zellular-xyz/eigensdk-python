import pytest
from base import *
from web3 import Web3
from unittest.mock import MagicMock


@pytest.fixture
def mock_allocation_manager(mocker):
    mock = mocker.MagicMock()
    mock.functions.getAllocationDelay.return_value.call.return_value = (True, 10)
    return mock


# ========================== ADDRESSES ========================== #

@pytest.fixture
def strategies():
    return [
        Web3.to_checksum_address("0x4444444444444444444444444444444444444444"),
        Web3.to_checksum_address("0x5555555555555555555555555555555555555555"),
    ]

@pytest.fixture
def operator():
    return Web3.to_checksum_address("0x1111111111111111111111111111111111111111")


@pytest.fixture
def avs_address():
    return Web3.to_checksum_address("0x3333333333333333333333333333333333333333")


@pytest.fixture
def strategy_address():
    return Web3.to_checksum_address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


@pytest.fixture
def account_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def staker_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def token():
    return Address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


@pytest.fixture
def encumbered_operator_address():
    return Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")


@pytest.fixture
def encumbered_strategy_address():
    return Web3.to_checksum_address("0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6")


@pytest.fixture
def max_magnitudes_operator_address():
    return Web3.to_checksum_address("0x5C69bEe701ef814a2B6a5C50c3C3BBFBE49D37A4")


@pytest.fixture
def allocation_operator_address():
    return Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")


@pytest.fixture
def allocation_strategy_address():
    return Web3.to_checksum_address("0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6")


@pytest.fixture
def operator_shares_operator_address():
    return Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def operator_sets_operator_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def allocation_delay_operator_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def registered_sets_operator_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def operator_address():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def delegation_approver():
    return Web3.to_checksum_address("0x11223344556677889900aabbccddeeff11223344")


@pytest.fixture
def pending_admin_address():
    return Address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


@pytest.fixture
def admin_address():
    return Address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


@pytest.fixture
def appointee_address():
    return Web3.to_checksum_address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


@pytest.fixture
def target():
    return Web3.to_checksum_address("0x11223344556677889900aabbccddeeff11223344")


# ========================== LISTS OF ADDRESSES ========================== #


@pytest.fixture
def max_magnitudes_strategy_addresses():
    return [
        Web3.to_checksum_address("0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"),
        Web3.to_checksum_address("0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"),
    ]


@pytest.fixture
def operator_shares_strategy_addresses():
    return [
        Web3.to_checksum_address("0x09635F643e140090A9A8Dcd712eD6285858ceBef"),
        Web3.to_checksum_address("0x11223344556677889900aabbccddeeff11223344"),
    ]


@pytest.fixture
def operator_addresses():
    return [
        Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678"),
    ]


@pytest.fixture
def strategy_addresses():
    return [
        Web3.to_checksum_address("0x09635F643e140090A9A8Dcd712eD6285858ceBef"),
        Web3.to_checksum_address("0x11223344556677889900aabbccddeeff11223344"),
    ]


# ========================== BLOCKCHAIN DATA ========================== #


@pytest.fixture
def block_number():
    return None  # Set to a specific block number if needed


@pytest.fixture
def expiry():
    return 1700000000  # Example Unix timestamp for expiry


@pytest.fixture
def selector():
    selector_bytes = bytes.fromhex("a3d1e5f4")  # Example function selector
    assert len(selector_bytes) == 4, "❌ Function selector must be exactly 4 bytes long"
    return selector_bytes


# ========================== HASHES AND SALTS ========================== #


@pytest.fixture
def salt():
    return bytes.fromhex(
        "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    )  # 32-byte salt


@pytest.fixture
def approver_salt():
    salt = bytes.fromhex(
        "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    )
    assert len(salt) == 32, "❌ approver_salt must be exactly 32 bytes long"
    return salt


@pytest.fixture
def withdrawal_root():
    root = bytes.fromhex(
        "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    )
    assert len(root) == 32, "❌ withdrawal_root must be exactly 32 bytes long"
    return root


@pytest.fixture
def root_hash():
    hash_bytes = bytes.fromhex(
        "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    )
    assert len(hash_bytes) == 32, "❌ Root hash must be exactly 32 bytes long"
    return hash_bytes


@pytest.fixture
def submission_hash():
    hash_bytes = bytes.fromhex(
        "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
    )
    assert len(hash_bytes) == 32, "❌ Submission hash must be exactly 32 bytes long"
    return hash_bytes


# ========================== SPECIAL ENTITIES ========================== #


@pytest.fixture
def staker():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def earner():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def submitter():
    return Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")


@pytest.fixture
def avs():
    return Address("0x09635F643e140090A9A8Dcd712eD6285858ceBef")


# ========================== CLAIM DATA ========================== #


@pytest.fixture
def claim():
    return {
        "root": bytes.fromhex(
            "a3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"
        ),
        "index": 1,
        "account": Address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
        "amount": 1000,
        "merkleProof": [
            bytes.fromhex(
                "b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4"
            ),
            bytes.fromhex(
                "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
            ),
        ],
    }


@pytest.fixture
def operator_set():
    """Fixture that returns a valid operator_set dictionary."""
    return {
        "Id": 1,  # Single Operator Set ID
        "Avs": "0x2222222222222222222222222222222222222222",
    }


@pytest.fixture
def strategy_address():
    return "0x09635F643e140090A9A8Dcd712eD6285858ceBef"


@pytest.fixture
def operator_sets():
    """Fixture to provide a list of operator sets."""
    return [
        {
            "id": 1,  # Ensure capital "Id"
            "avs": "0x2222222222222222222222222222222222222222",
        },
        {
            "id": 2,  # Ensure capital "Id"
            "avs": "0x3333333333333333333333333333333333333333",
        },
    ]


@pytest.fixture
def future_block():
    """Fixture to provide a mock future block number."""
    return 2000000  # Example future block number
