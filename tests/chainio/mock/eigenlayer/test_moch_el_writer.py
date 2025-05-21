import unittest
from unittest.mock import MagicMock, patch
from web3 import Web3
from web3.types import TxReceipt

from eigensdk.chainio.clients.elcontracts.writer import ELWriter


class TestELWriter(unittest.TestCase):
    def setUp(self):
        self.mock_allocation_manager = MagicMock()
        self.mock_avs_directory = MagicMock()
        self.mock_delegation_manager = MagicMock()
        self.mock_permission_controller = MagicMock()
        self.mock_reward_coordinator = MagicMock()
        self.mock_registry_coordinator = MagicMock()
        self.mock_strategy_manager = MagicMock()
        self.mock_el_chain_reader = MagicMock()
        self.mock_eth_http_client = MagicMock()
        self.mock_logger = MagicMock()
        self.mock_pk_wallet = MagicMock()
        self.mock_strategy_abi = MagicMock()
        self.mock_erc20_abi = MagicMock()

        self.el_writer = ELWriter(
            self.mock_allocation_manager,
            self.mock_avs_directory,
            self.mock_delegation_manager,
            self.mock_permission_controller,
            self.mock_reward_coordinator,
            self.mock_registry_coordinator,
            self.mock_strategy_manager,
            self.mock_el_chain_reader,
            self.mock_eth_http_client,
            self.mock_logger,
            self.mock_pk_wallet,
            self.mock_strategy_abi,
            self.mock_erc20_abi,
        )

    @patch("eigensdk.chainio.clients.elcontracts.writer.send_transaction")
    def test_remove_pending_admin(self, mock_send_transaction):
        account_address = "0x1234567890123456789012345678901234567890"
        admin_address = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        mock_receipt = MagicMock(spec=TxReceipt)
        mock_send_transaction.return_value = mock_receipt
        mock_function = MagicMock()
        self.mock_permission_controller.functions.removePendingAdmin.return_value = mock_function
        request = {"account_address": account_address, "admin_address": admin_address}
        result = self.el_writer.remove_pending_admin(request)
        self.mock_permission_controller.functions.removePendingAdmin.assert_called_once_with(
            Web3.to_checksum_address(account_address), Web3.to_checksum_address(admin_address)
        )
        mock_send_transaction.assert_called_once_with(
            mock_function, self.mock_pk_wallet, self.mock_eth_http_client
        )
        self.assertEqual(result, mock_receipt)

    @patch("eigensdk.chainio.clients.elcontracts.writer.send_transaction")
    def test_process_claim(self, mock_send_transaction):
        recipient_address = "0x9876543210987654321098765432109876543210"
        claim = {
            "rootIndex": 1,
            "earnerIndex": 2,
            "earnerTreeProof": b"proof1",
            "earnerLeaf": {
                "earner": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
                "earnerTokenRoot": "0x2b961e3959b79326a8e7f64ef0d2d825707669b5",
            },
            "tokenIndices": [3, 4],
            "tokenTreeProofs": [b"proof2", b"proof3"],
            "tokenLeaves": [
                {
                    "token": "0x2b961e3959b79326a8e7f64ef0d2d825707669b5",
                    "cumulativeEarnings": "1000000000000000000",
                },
                {
                    "token": "0x2b961e3959b79326a8e7f64ef0d2d825707669b5",
                    "cumulativeEarnings": "2000000000000000000",
                },
            ],
        }
        expected_claim_tuple = (
            1,
            2,
            b"proof1",
            (
                Web3.to_checksum_address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                "0x2b961e3959b79326a8e7f64ef0d2d825707669b5",
            ),
            [3, 4],
            [b"proof2", b"proof3"],
            [
                (
                    Web3.to_checksum_address("0x2b961e3959b79326a8e7f64ef0d2d825707669b5"),
                    1000000000000000000,
                ),
                (
                    Web3.to_checksum_address("0x2b961e3959b79326a8e7f64ef0d2d825707669b5"),
                    2000000000000000000,
                ),
            ],
        )
        mock_receipt = MagicMock(spec=TxReceipt)
        mock_send_transaction.return_value = mock_receipt
        mock_function = MagicMock()
        self.mock_reward_coordinator.functions.processClaim.return_value = mock_function
        result = self.el_writer.process_claim(claim, recipient_address)
        self.mock_reward_coordinator.functions.processClaim.assert_called_once_with(
            expected_claim_tuple, Web3.to_checksum_address(recipient_address)
        )
        mock_send_transaction.assert_called_once_with(
            mock_function, self.mock_pk_wallet, self.mock_eth_http_client
        )
        self.assertEqual(result, mock_receipt)

    @patch("eigensdk.chainio.clients.elcontracts.writer.send_transaction")
    def test_modify_allocations(self, mock_send_transaction):
        operator_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        avs_service_manager = "0x2b961e3959b79326a8e7f64ef0d2d825707669b5"
        operator_set_id = 42
        strategies = [
            "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
            "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
        ]
        new_magnitudes = [1000000, 2000000]
        expected_allocation = (
            (Web3.to_checksum_address(avs_service_manager), operator_set_id),
            [Web3.to_checksum_address(s) for s in strategies],
            new_magnitudes,
        )
        mock_receipt = MagicMock(spec=TxReceipt)
        mock_send_transaction.return_value = mock_receipt
        mock_function = MagicMock()
        self.mock_allocation_manager.functions.modifyAllocations.return_value = mock_function
        result = self.el_writer.modify_allocations(
            operator_address, avs_service_manager, operator_set_id, strategies, new_magnitudes
        )
        self.mock_allocation_manager.functions.modifyAllocations.assert_called_once_with(
            Web3.to_checksum_address(operator_address), [expected_allocation]
        )
        mock_send_transaction.assert_called_once_with(
            mock_function, self.mock_pk_wallet, self.mock_eth_http_client
        )
        self.assertEqual(result, mock_receipt)

    @patch('eigensdk.chainio.clients.elcontracts.writer.send_transaction')
    @patch('eigensdk.chainio.clients.elcontracts.writer.abi_encode_normal_registration_params')
    @patch('eigensdk.chainio.clients.elcontracts.writer.get_pubkey_registration_params')
    def test_register_for_operator_sets(self, mock_get_pubkey_params, mock_encode_params, mock_send_transaction):
        # Set up test data
        registry_coordinator_addr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        operator_address = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"
        avs_address = "0x2b961e3959b79326a8e7f64ef0d2d825707669b5"
        operator_set_ids = [1, 2, 3]
        socket = "localhost:8080"
        bls_key_pair = {"pubkey": "0x123", "privkey": "0x456"}
        
        # Create request dict
        request = {
            "operator_address": operator_address,
            "avs_address": avs_address,
            "operator_set_ids": operator_set_ids,
            "socket": socket,
            "bls_key_pair": bls_key_pair
        }
        
        # Set up mocks but don't assert on implementation details
        # Just make sure isOperator is mocked to return True
        is_operator_call = MagicMock()
        is_operator_call.call.return_value = True
        self.mock_delegation_manager.functions.isOperator.return_value = is_operator_call
        
        # Mock the pubkey registration params
        mock_pubkey_params = {"pubkeyG1": "0x123", "pubkeyG2": "0x456"}
        mock_get_pubkey_params.return_value = mock_pubkey_params
        
        # Mock the encoded data
        mock_encoded_data = b"encoded_registration_data"
        mock_encode_params.return_value = mock_encoded_data
        
        # Mock the register function
        mock_function = MagicMock()
        self.mock_allocation_manager.functions.registerForOperatorSets.return_value = mock_function
        
        # Mock the transaction receipt
        mock_receipt = MagicMock(spec=TxReceipt)
        mock_send_transaction.return_value = mock_receipt
        
        # Expected register_params
        expected_register_params = {
            "avs": Web3.to_checksum_address(avs_address),
            "operatorSetIds": operator_set_ids,
            "data": mock_encoded_data
        }
        
        # Call the method under test
        result = self.el_writer.register_for_operator_sets(registry_coordinator_addr, request)
        
        # Verify only the essential assertions
        # Don't check implementation details like isOperator call
        mock_get_pubkey_params.assert_called_once_with(
            self.mock_eth_http_client,
            Web3.to_checksum_address(registry_coordinator_addr),
            Web3.to_checksum_address(operator_address),
            bls_key_pair
        )
        
        mock_encode_params.assert_called_once_with(
            0,  # RegistrationType.NORMAL
            socket,
            mock_pubkey_params
        )
        
        self.mock_allocation_manager.functions.registerForOperatorSets.assert_called_once_with(
            Web3.to_checksum_address(operator_address),
            expected_register_params
        )
        
        # Verify send_transaction was called with the right parameters
        mock_send_transaction.assert_called_once_with(
            mock_function,
            self.mock_pk_wallet,
            self.mock_eth_http_client
        )
        
        # Verify return value
        self.assertEqual(result, mock_receipt)

    @patch("eigensdk.chainio.clients.elcontracts.writer.send_transaction")
    def test_deregister_from_operator_sets(self, mock_send_transaction):
        operator_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        avs_address = "0x2b961e3959b79326a8e7f64ef0d2d825707669b5"
        operator_set_ids = [1, 2, 3]
        request = {"avs_address": avs_address, "operator_set_ids": operator_set_ids}
        expected_params = {
            "operator": Web3.to_checksum_address(operator_address),
            "avs": Web3.to_checksum_address(avs_address),
            "operatorSetIds": operator_set_ids,
        }
        mock_function = MagicMock()
        self.mock_allocation_manager.functions.deregisterFromOperatorSets.return_value = (
            mock_function
        )
        mock_receipt = MagicMock(spec=TxReceipt)
        mock_send_transaction.return_value = mock_receipt
        result = self.el_writer.deregister_from_operator_sets(operator_address, request)
        self.mock_allocation_manager.functions.deregisterFromOperatorSets.assert_called_once_with(
            expected_params
        )
        mock_send_transaction.assert_called_once_with(
            mock_function, self.mock_pk_wallet, self.mock_eth_http_client
        )
        self.assertEqual(result, mock_receipt)


if __name__ == "__main__":
    unittest.main()
