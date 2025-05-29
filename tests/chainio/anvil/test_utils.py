from unittest.mock import MagicMock, patch

from eth_account import Account
from web3 import Web3
from web3.contract.contract import ContractFunction

from eigensdk.chainio.utils import (
    nums_to_bytes,
    bitmap_to_quorum_ids,
    send_transaction,
    remove_duplicate_strategies,
    convert_bn254_geth_to_gnark,
    convert_to_bn254_g1_point,
)
from eigensdk.crypto.bls.attestation import G1Point


class TestUtils:
    def test_nums_to_bytes(self):
        # Test conversion from list of integers to bytes
        result = nums_to_bytes([65, 66, 67])  # ASCII for 'ABC'
        assert result == b"ABC"

        result = nums_to_bytes([])
        assert result == b""

        result = nums_to_bytes([0, 1, 2])
        assert result == b"\x00\x01\x02"

    def test_bitmap_to_quorum_ids(self):
        # Test conversion from bitmap to quorum IDs
        # Empty bitmap (no quorums)
        assert bitmap_to_quorum_ids(0) == []

        # Bitmap with quorum 0 set
        assert bitmap_to_quorum_ids(1) == [0]

        # Bitmap with quorums 0, 2, and 4 set (binary: 10101)
        assert bitmap_to_quorum_ids(21) == [0, 2, 4]

        # Bitmap with all quorums set up to 3 (binary: 1111)
        assert bitmap_to_quorum_ids(15) == [0, 1, 2, 3]

        # Test large bitmap
        assert bitmap_to_quorum_ids(1 << 100) == [100]

    @patch("eigensdk.chainio.utils.send_transaction")
    def test_send_transaction(self, mock_send_transaction):
        # Create mock objects
        mock_func = MagicMock(spec=ContractFunction)
        mock_wallet = MagicMock()
        mock_web3 = MagicMock()
        mock_receipt = MagicMock()

        # Configure mocks
        mock_wallet.address = "0x1234567890123456789012345678901234567890"
        mock_wallet.key = b"private_key_bytes"
        mock_web3.eth.gas_price = 20000000000  # 20 Gwei
        mock_web3.eth.get_transaction_count.return_value = 5
        mock_web3.eth.chain_id = 31337  # Anvil chain ID
        mock_web3.eth.account.sign_transaction.return_value.raw_transaction = b"signed_tx_bytes"
        mock_web3.eth.send_raw_transaction.return_value = b"tx_hash"
        mock_web3.eth.wait_for_transaction_receipt.return_value = mock_receipt

        # Set up the mock function
        mock_func.build_transaction.return_value = {
            "from": mock_wallet.address,
            "gas": 1000000,
            "gasPrice": mock_web3.eth.gas_price,
            "nonce": 5,
            "chainId": 31337,
        }

        # Call the function
        result = send_transaction(mock_func, mock_wallet, mock_web3, gas_limit=1000000)

        # Verify interactions
        mock_func.build_transaction.assert_called_once()
        mock_web3.eth.account.sign_transaction.assert_called_once()
        mock_web3.eth.send_raw_transaction.assert_called_once_with(b"signed_tx_bytes")
        mock_web3.eth.wait_for_transaction_receipt.assert_called_once_with(b"tx_hash")

        # Verify result
        assert result == mock_receipt

    def test_remove_duplicate_strategies(self):
        # Test empty list
        assert remove_duplicate_strategies([]) == []

        # Test list with no duplicates
        strategies = ["0x1", "0x2", "0x3"]
        assert remove_duplicate_strategies(strategies) == ["0x1", "0x2", "0x3"]

        # Test list with duplicates
        strategies_with_duplicates = ["0x1", "0x2", "0x1", "0x3", "0x2"]
        assert remove_duplicate_strategies(strategies_with_duplicates) == ["0x1", "0x2", "0x3"]

        # Test sorting
        unsorted_strategies = ["0x3", "0x1", "0x2"]
        assert remove_duplicate_strategies(unsorted_strategies) == ["0x1", "0x2", "0x3"]

    def test_bn254_g1_point_conversion(self):
        # Create G1Point
        g1_point = G1Point(123, 456)

        # Convert to BN254G1Point
        bn254_point = convert_to_bn254_g1_point(g1_point)

        # Verify conversion
        assert bn254_point.X == 123
        assert bn254_point.Y == 456

        # Convert back to G1Point
        converted_g1_point = convert_bn254_geth_to_gnark(bn254_point)

        # Verify round-trip conversion
        assert int(converted_g1_point.x.getStr()) == 123
        assert int(converted_g1_point.y.getStr()) == 456


# More tests could be added for the remaining functions
