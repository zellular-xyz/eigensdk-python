import pytest
from unittest.mock import Mock, patch, MagicMock
from web3.exceptions import ContractLogicError, BlockNotFound
from tests.builder import *
from typing import List, Dict, Any, Tuple, Optional
from web3.contract.contract import Contract
from eigensdk.chainio.clients.avsregistry.writer import AvsRegistryWriter
import ecdsa
from eigensdk.crypto.bls.attestation import BLSKeyPair, G1Point


class TestAvsRegistryWriter:

    @pytest.fixture
    def avs_registry_writer(self):
        """Create a mock AvsRegistryWriter instance with necessary mock objects."""
        registry_coordinator = Mock(spec=Contract)
        operator_state_retriever = Mock(spec=Contract)
        service_manager = Mock(spec=Contract)
        service_manager_addr = "0x1234567890123456789012345678901234567890"
        stake_registry = Mock(spec=Contract)
        bls_apk_registry = Mock(spec=Contract)
        el_reader = Mock()
        logger = Mock()
        eth_client = Mock()

        writer = AvsRegistryWriter(
            registry_coordinator=registry_coordinator,
            operator_state_retriever=operator_state_retriever,
            service_manager=service_manager,
            service_manager_addr=service_manager_addr,
            stake_registry=stake_registry,
            bls_apk_registry=bls_apk_registry,
            el_reader=el_reader,
            logger=logger,
            eth_client=eth_client,
        )

        # Add tx_mgr attribute which is used in methods but not in constructor
        writer.tx_mgr = Mock()
        writer.tx_mgr.get_no_send_tx_opts = Mock(return_value={"from": "0x1234"})
        writer.tx_mgr.send = Mock(return_value={"transactionHash": b"0x1234"})

        # Mock web3 attribute for methods that use it
        writer.web3 = Mock()
        writer.web3.eth = Mock()
        writer.web3.eth.contract = Mock(return_value=Mock())
        writer.web3.eth.account = Mock()
        writer.web3.eth.account.sign_message = Mock()
        writer.web3.eth.account.from_key = Mock(return_value=Mock(address="0xOperatorAddress"))
        writer.web3.eth.block_number = 12345
        writer.web3.eth.get_block = Mock(return_value={"timestamp": 1234567890})

        return writer

    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_bn254_geth_to_gnark")
    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_to_bn254_g1_point")
    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_to_bn254_g2_point")
    def test_register_operator(
        self, mock_convert_g2, mock_convert_g1, mock_convert_gnark, avs_registry_writer
    ):
        # Setup mock private key
        mock_private_key = Mock(spec=ecdsa.SigningKey)
        mock_private_key.to_string.return_value = b"mock_private_key_bytes"

        # Setup mock BLS key pair
        mock_bls_key_pair = Mock()
        mock_signature = Mock()
        mock_signature.g1_point = "mock_g1_signature"
        mock_bls_key_pair.sign_hashed_to_curve_message.return_value = mock_signature
        mock_bls_key_pair.get_pub_key_g1.return_value = "mock_g1_pubkey"
        mock_bls_key_pair.get_pub_key_g2.return_value = "mock_g2_pubkey"

        # Setup converted values
        mock_convert_gnark.return_value = "converted_hashed_msg"
        mock_convert_g1.return_value = "converted_g1_pubkey"
        mock_convert_g2.return_value = "converted_g2_pubkey"

        # Setup quorum numbers
        mock_quorum_numbers = Mock()
        mock_quorum_numbers.underlying_type.return_value = [1, 2, 3]

        # Setup registry coordinator mock returns
        avs_registry_writer.registry_coordinator.functions.pubkeyRegistrationMessageHash.return_value.call.return_value = (
            "hashed_msg"
        )

        # Setup el_reader mock returns
        avs_registry_writer.el_reader.functions.calculateOperatorAVSRegistrationDigestHash.return_value.call.return_value = (
            b"msg_to_sign"
        )

        # Setup mock signature
        mock_signature_obj = Mock()
        mock_signature_obj.signature = b"mock_signature\x01"  # Last byte will be modified
        avs_registry_writer.web3.eth.account.sign_message.return_value = mock_signature_obj

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.registerOperator.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Mock os.urandom
        with patch("os.urandom", return_value=b"mock_salt" * 2):
            # Call the function
            result = avs_registry_writer.register_operator(
                operator_ecdsa_private_key=mock_private_key,
                bls_key_pair=mock_bls_key_pair,
                quorum_numbers=mock_quorum_numbers,
                socket="mock_socket",
                wait_for_receipt=True,
            )

            # Assertions
            assert result == {"transactionHash": b"0x1234"}

            # Verify BLS signature was created
            avs_registry_writer.registry_coordinator.functions.pubkeyRegistrationMessageHash.assert_called_once_with(
                "0xOperatorAddress"
            )
            mock_bls_key_pair.sign_hashed_to_curve_message.assert_called_once_with(
                "converted_hashed_msg"
            )
            mock_convert_gnark.assert_called_once_with("hashed_msg")

            # Verify pubkey conversions
            mock_convert_g1.assert_called_once_with("mock_g1_pubkey")
            mock_convert_g2.assert_called_once_with("mock_g2_pubkey")

            # Verify operator signature creation
            avs_registry_writer.el_reader.functions.calculateOperatorAVSRegistrationDigestHash.assert_called_once()
            avs_registry_writer.web3.eth.account.sign_message.assert_called_once_with(
                b"msg_to_sign", mock_private_key
            )

            # Verify transaction was built correctly
            avs_registry_writer.registry_coordinator.functions.registerOperator.assert_called_once()
            avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

            # Verify logging happened
            assert avs_registry_writer.logger.info.call_count == 2

    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_bn254_geth_to_gnark")
    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_to_bn254_g1_point")
    @patch("eigensdk.chainio.clients.avsregistry.writer.convert_to_bn254_g2_point")
    def test_register_operator_with_churn(
        self, mock_convert_g2, mock_convert_g1, mock_convert_gnark, avs_registry_writer
    ):
        # Setup mock private keys
        mock_operator_private_key = Mock(spec=ecdsa.SigningKey)
        mock_operator_private_key.to_string.return_value = b"mock_private_key_bytes"

        mock_churn_approval_private_key = Mock(spec=ecdsa.SigningKey)
        mock_churn_approval_private_key.to_string.return_value = (
            b"mock_churn_approval_private_key_bytes"
        )

        # Setup mock BLS key pair - use Mock with no spec to allow any method
        mock_g1_pubkey = Mock()
        # Use a valid hex string for the operator ID
        mock_g1_pubkey.get_operator_id.return_value = (
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )

        mock_bls_key_pair = Mock()  # No spec to avoid method name constraints
        mock_signature = Mock()
        mock_signature.g1_point = "mock_g1_signature"
        mock_bls_key_pair.sign_hashed_to_curve_message.return_value = mock_signature

        # Explicitly set methods with the names used in the implementation
        mock_bls_key_pair.get_pub_key_g1 = Mock(return_value=mock_g1_pubkey)
        mock_bls_key_pair.get_pub_key_g2 = Mock(return_value="mock_g2_pubkey")

        # Setup converted values
        mock_convert_gnark.return_value = "converted_hashed_msg"
        mock_convert_g1.return_value = "converted_g1_pubkey"
        mock_convert_g2.return_value = "converted_g2_pubkey"

        # Setup quorum numbers
        mock_quorum_numbers = Mock()
        mock_quorum_numbers.underlying_type.return_value = [1, 2, 3]

        # Setup quorum numbers to kick and operators to kick
        mock_quorum_numbers_to_kick = [Mock(), Mock()]
        mock_quorum_numbers_to_kick[0].underlying_type.return_value = 0
        mock_quorum_numbers_to_kick[1].underlying_type.return_value = 1
        operators_to_kick = ["0xOperatorToKick1", "0xOperatorToKick2"]

        # Setup registry coordinator mock returns
        avs_registry_writer.registry_coordinator.functions.pubkeyRegistrationMessageHash.return_value.call.return_value = (
            "hashed_msg"
        )
        avs_registry_writer.registry_coordinator.functions.calculateOperatorChurnApprovalDigestHash.return_value.call.return_value = (
            b"churn_msg_to_sign"
        )

        # Setup el_reader mock returns
        avs_registry_writer.el_reader.functions.calculateOperatorAVSRegistrationDigestHash.return_value.call.return_value = (
            b"msg_to_sign"
        )

        # Setup mock signatures
        mock_operator_signature = Mock()
        mock_operator_signature.signature = (
            b"mock_operator_signature\x01"  # Last byte will be modified
        )

        mock_churn_signature = Mock()
        mock_churn_signature.signature = (
            b"mock_churn_approval_signature\x02"  # Last byte will be modified
        )

        # Setup sign_message to return different values for different calls
        avs_registry_writer.web3.eth.account.sign_message.side_effect = [
            mock_operator_signature,  # First call (operator signature)
            mock_churn_signature,  # Second call (churn approval signature)
        ]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.registerOperatorWithChurn.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Mock os.urandom to return consistent values for testing
        with patch("os.urandom", side_effect=[b"mock_salt" * 2, b"mock_churn_salt" * 2]):
            # Call the function
            result = avs_registry_writer.register_operator_with_churn(
                operator_ecdsa_private_key=mock_operator_private_key,
                churn_approval_ecdsa_private_key=mock_churn_approval_private_key,
                bls_key_pair=mock_bls_key_pair,
                quorum_numbers=mock_quorum_numbers,
                quorum_numbers_to_kick=mock_quorum_numbers_to_kick,
                operators_to_kick=operators_to_kick,
                socket="mock_socket",
                wait_for_receipt=True,
            )

            # Assertions
            assert result == {"transactionHash": b"0x1234"}

            # Verify BLS signature was created
            avs_registry_writer.registry_coordinator.functions.pubkeyRegistrationMessageHash.assert_called_once_with(
                "0xOperatorAddress"
            )
            mock_bls_key_pair.sign_hashed_to_curve_message.assert_called_once_with(
                "converted_hashed_msg"
            )
            mock_convert_gnark.assert_called_once_with("hashed_msg")

            # Verify pubkey conversions - expect get_pub_key_g1 to be called twice
            assert mock_bls_key_pair.get_pub_key_g1.call_count == 2
            mock_bls_key_pair.get_pub_key_g2.assert_called_once()
            mock_convert_g1.assert_called_once_with(mock_g1_pubkey)
            mock_convert_g2.assert_called_once_with("mock_g2_pubkey")

            # Verify operator signature creation
            avs_registry_writer.el_reader.functions.calculateOperatorAVSRegistrationDigestHash.assert_called_once_with(
                "0xOperatorAddress",
                avs_registry_writer.service_manager_addr,
                b"mock_salt" * 2,
                1234567890 + 3600,  # timestamp + 1 hour
            )

            # Verify operator churn approval signature creation
            expected_operator_kick_params = [
                {"operator": "0xOperatorToKick1", "quorumNumber": 0},
                {"operator": "0xOperatorToKick2", "quorumNumber": 1},
            ]

            avs_registry_writer.registry_coordinator.functions.calculateOperatorChurnApprovalDigestHash.assert_called_once_with(
                "0xOperatorAddress",
                bytes.fromhex(
                    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                ),  # removing '0x' prefix
                expected_operator_kick_params,
                b"mock_churn_salt" * 2,
                1234567890 + 3600,  # timestamp + 1 hour
            )

            # Verify sign_message calls
            sign_message_calls = avs_registry_writer.web3.eth.account.sign_message.call_args_list
            assert len(sign_message_calls) == 2

            # First call (operator signature)
            assert sign_message_calls[0][0][0] == b"msg_to_sign"
            assert sign_message_calls[0][0][1] == mock_operator_private_key

            # Second call (churn approval signature)
            assert sign_message_calls[1][0][0] == b"churn_msg_to_sign"
            assert sign_message_calls[1][0][1] == mock_churn_approval_private_key

            # Verify transaction was built correctly
            avs_registry_writer.registry_coordinator.functions.registerOperatorWithChurn.assert_called_once()

            # Check arguments for registerOperatorWithChurn
            call_args = avs_registry_writer.registry_coordinator.functions.registerOperatorWithChurn.call_args[
                0
            ]
            assert call_args[0] == {"from": "0x1234"}  # tx_opts
            assert call_args[1] == [1, 2, 3]  # quorum_numbers
            assert call_args[2] == "mock_socket"  # socket

            # Verify pubkey_reg_params (arg 3)
            assert call_args[3]["pubkeyRegistrationSignature"] == "mock_g1_signature"
            assert call_args[3]["pubkeyG1"] == "converted_g1_pubkey"
            assert call_args[3]["pubkeyG2"] == "converted_g2_pubkey"

            # Verify operator_kick_params (arg 4)
            assert len(call_args[4]) == 2
            assert call_args[4][0]["operator"] == "0xOperatorToKick1"
            assert call_args[4][0]["quorumNumber"] == 0
            assert call_args[4][1]["operator"] == "0xOperatorToKick2"
            assert call_args[4][1]["quorumNumber"] == 1

            # Verify both signature objects were constructed correctly
            assert "signature" in call_args[5]  # churn_approver_signature
            assert "salt" in call_args[5]
            assert "expiry" in call_args[5]

            assert "signature" in call_args[6]  # operator_signature
            assert "salt" in call_args[6]
            assert "expiry" in call_args[6]

            # Verify transaction was sent
            avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

            # Verify logging happened
            assert avs_registry_writer.logger.info.call_count == 1

            # Verify log contains expected information
            log_call = avs_registry_writer.logger.info.call_args
            assert "successfully registered operator" in log_call[0][0]
            assert log_call[1]["extra"]["txHash"] == b"0x1234".hex()
            assert (
                log_call[1]["extra"]["avs-service-manager"]
                == avs_registry_writer.service_manager_addr
            )
            assert log_call[1]["extra"]["operator"] == "0xOperatorAddress"
            assert log_call[1]["extra"]["quorumNumbers"] == mock_quorum_numbers

    def test_update_stakes_of_entire_operator_set_for_quorums(self, avs_registry_writer):
        # Setup test data
        operators_per_quorum = [
            ["0xOperator1", "0xOperator2"],  # Operators for quorum 0
            ["0xOperator3", "0xOperator4"],  # Operators for quorum 1
        ]

        # Setup quorum numbers
        mock_quorum_numbers = Mock()
        mock_quorum_numbers.underlying_type.return_value = [0, 1]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.updateOperatorsForQuorum.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
            operators_per_quorum=operators_per_quorum,
            quorum_numbers=mock_quorum_numbers,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.updateOperatorsForQuorum.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            operators_per_quorum,
            [0, 1],  # underlying_type() return value
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 2

        # Verify the first log contains quorum numbers in the extra data
        first_log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert first_log_call[1]["extra"]["quorumNumbers"] == mock_quorum_numbers

        # Verify the second log contains transaction hash and quorum numbers
        second_log_call = avs_registry_writer.logger.info.call_args_list[1]
        assert second_log_call[1]["extra"]["txHash"] == b"0x1234".hex()
        assert second_log_call[1]["extra"]["quorumNumbers"] == mock_quorum_numbers

    def test_update_stakes_of_operator_subset_for_all_quorums(self, avs_registry_writer):
        # Setup test data
        operators = ["0xOperator1", "0xOperator2", "0xOperator3"]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.updateOperators.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(
            operators=operators, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.updateOperators.assert_called_once_with(
            {"from": "0x1234"}, operators  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 2

        # Verify the first log contains operators in the extra data
        first_log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert first_log_call[1]["extra"]["operators"] == operators

        # Verify the second log contains transaction hash and operators
        second_log_call = avs_registry_writer.logger.info.call_args_list[1]
        assert second_log_call[1]["extra"]["txHash"] == b"0x1234".hex()
        assert second_log_call[1]["extra"]["operators"] == operators

    def test_deregister_operator(self, avs_registry_writer):
        # Setup quorum numbers
        mock_quorum_numbers = Mock()
        mock_quorum_numbers.underlying_type.return_value = [0, 1, 2]

        # Setup mock pubkey (note: it's not actually used in the method implementation)
        mock_pubkey = Mock(name="BN254G1Point")

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.deregisterOperator0.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.deregister_operator(
            quorum_numbers=mock_quorum_numbers,
            pubkey=mock_pubkey,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.deregisterOperator0.assert_called_once_with(
            {"from": "0x1234"}, [0, 1, 2]  # tx_opts  # underlying_type() return value
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 2

        # Verify the first log message
        first_log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "deregistering operator" in first_log_call[0][0]

        # Verify the second log contains transaction hash
        second_log_call = avs_registry_writer.logger.info.call_args_list[1]
        assert "successfully deregistered" in second_log_call[0][0]
        assert second_log_call[1]["extra"]["txHash"] == b"0x1234".hex()

    def test_update_socket(self, avs_registry_writer):
        # Setup test data
        socket = "example.com:8080"

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.updateSocket.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.update_socket(socket=socket, wait_for_receipt=True)

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.updateSocket.assert_called_once_with(
            {"from": "0x1234"}, socket  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Note: This method doesn't have logging statements, so we don't verify logs

    def test_set_rewards_initiator(self, avs_registry_writer):
        # Setup test data
        rewards_initiator_addr = "0xRewardsInitiatorAddress"

        # Setup mock service manager contract
        mock_service_manager_contract = Mock()
        mock_service_manager_contract.functions.setRewardsInitiator.return_value.build_transaction.return_value = {
            "gas": 1000000
        }

        # Setup web3.eth.contract to return the mock service manager contract
        avs_registry_writer.web3.eth.contract.return_value = mock_service_manager_contract

        # Add service_manager_abi attribute which is used in the method
        avs_registry_writer.service_manager_abi = "mock_service_manager_abi"

        # Call the function
        result = avs_registry_writer.set_rewards_initiator(
            rewards_initiator_addr=rewards_initiator_addr, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify contract was created correctly
        avs_registry_writer.web3.eth.contract.assert_called_once_with(
            address=avs_registry_writer.service_manager_addr,
            abi=avs_registry_writer.service_manager_abi,
        )

        # Verify transaction was built correctly
        mock_service_manager_contract.functions.setRewardsInitiator.assert_called_once_with(
            {"from": "0x1234"}, rewards_initiator_addr  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with({"gas": 1000000}, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log message content
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting rewards initiator" in log_call[0][0]
        assert log_call[1]["extra"]["rewardsInitiatorAddr"] == rewards_initiator_addr

    def test_set_slashable_stake_lookahead(self, avs_registry_writer):
        # Setup test data
        quorum_number = 2
        look_ahead_period = 100  # blocks

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.stake_registry.functions.setSlashableStakeLookahead.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_slashable_stake_lookahead(
            quorum_number=quorum_number,
            look_ahead_period=look_ahead_period,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.stake_registry.functions.setSlashableStakeLookahead.assert_called_once_with(
            {"from": "0x1234"}, quorum_number, look_ahead_period  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

    def test_set_minimum_stake_for_quorum(self, avs_registry_writer):
        # Setup test data
        quorum_number = 3
        minimum_stake = 32000000000  # 32 ETH in wei

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.stake_registry.functions.setMinimumStakeForQuorum.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_minimum_stake_for_quorum(
            quorum_number=quorum_number,
            minimum_stake=minimum_stake,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.stake_registry.functions.setMinimumStakeForQuorum.assert_called_once_with(
            {"from": "0x1234"}, quorum_number, minimum_stake  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

    def test_create_total_delegated_stake_quorum(self, avs_registry_writer):
        # Setup test data
        operator_set_params = {
            "maxOperatorCount": 100,
            "kickBIPsOfOperatorStake": 1000,  # 10% in basis points
            "kickBIPsOfTotalStake": 500,  # 5% in basis points
        }

        minimum_stake_required = 32000000000  # 32 ETH in wei

        strategy_params = [
            {
                "strategyAddress": "0xStrategy1Address",
                "multiplier": 10000,  # 100% in basis points
            },
            {
                "strategyAddress": "0xStrategy2Address",
                "multiplier": 5000,  # 50% in basis points
            },
        ]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.createTotalDelegatedStakeQuorum.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.create_total_delegated_stake_quorum(
            operator_set_params=operator_set_params,
            minimum_stake_required=minimum_stake_required,
            strategy_params=strategy_params,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.createTotalDelegatedStakeQuorum.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            operator_set_params,
            minimum_stake_required,
            strategy_params,
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log message content
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "Creating total delegated stake quorum" in log_call[0][0]

    def test_create_slashable_stake_quorum(self, avs_registry_writer):
        # Setup test data
        operator_set_params = {
            "maxOperatorCount": 80,
            "kickBIPsOfOperatorStake": 1500,  # 15% in basis points
            "kickBIPsOfTotalStake": 700,  # 7% in basis points
        }

        minimum_stake_required = 16000000000  # 16 ETH in wei

        strategy_params = [
            {
                "strategyAddress": "0xStrategyAAddress",
                "multiplier": 8000,  # 80% in basis points
            },
            {
                "strategyAddress": "0xStrategyBAddress",
                "multiplier": 12000,  # 120% in basis points
            },
        ]

        look_ahead_period = 100  # blocks

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.createSlashableStakeQuorum.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.create_slashable_stake_quorum(
            operator_set_params=operator_set_params,
            minimum_stake_required=minimum_stake_required,
            strategy_params=strategy_params,
            look_ahead_period=look_ahead_period,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.createSlashableStakeQuorum.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            operator_set_params,
            minimum_stake_required,
            strategy_params,
            look_ahead_period,
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log message content
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "Creating slashable stake quorum" in log_call[0][0]

    def test_eject_operator(self, avs_registry_writer):
        # Setup test data
        operator_address = "0xEjectedOperatorAddress"

        # Setup quorum numbers
        mock_quorum_numbers = Mock()
        mock_quorum_numbers.underlying_type.return_value = [1, 2, 3]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.ejectOperator.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.eject_operator(
            operator_address=operator_address,
            quorum_numbers=mock_quorum_numbers,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.ejectOperator.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            operator_address,
            [1, 2, 3],  # underlying_type() return value
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains operator address and quorum numbers
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "ejecting operator" in log_call[0][0]
        assert log_call[1]["extra"]["operator_address"] == operator_address
        assert log_call[1]["extra"]["quorumNumbers"] == mock_quorum_numbers

    def test_set_operator_set_params(self, avs_registry_writer):
        # Setup test data
        quorum_number = 2
        operator_set_params = {
            "maxOperatorCount": 120,
            "kickBIPsOfOperatorStake": 2000,  # 20% in basis points
            "kickBIPsOfTotalStake": 800,  # 8% in basis points
        }

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.setOperatorSetParams.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_operator_set_params(
            quorum_number=quorum_number,
            operator_set_params=operator_set_params,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.setOperatorSetParams.assert_called_once_with(
            {"from": "0x1234"}, quorum_number, operator_set_params  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains quorum number
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting operator set params for quorum" in log_call[0][0]
        assert log_call[1]["extra"]["quorumNumber"] == quorum_number

    def test_set_churn_approver(self, avs_registry_writer):
        # Setup test data
        churn_approver_address = "0xChurnApproverAddress"

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.setChurnApprover.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_churn_approver(
            churn_approver_address=churn_approver_address, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.setChurnApprover.assert_called_once_with(
            {"from": "0x1234"}, churn_approver_address  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains churn approver address
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting churn approver" in log_call[0][0]
        assert log_call[1]["extra"]["churnApproverAddress"] == churn_approver_address

    def test_set_ejector(self, avs_registry_writer):
        # Setup test data
        ejector_address = "0xEjectorAddress"

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.setEjector.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_ejector(
            ejector_address=ejector_address, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.setEjector.assert_called_once_with(
            {"from": "0x1234"}, ejector_address  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains ejector address
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting ejector" in log_call[0][0]
        assert log_call[1]["extra"]["ejectorAddress"] == ejector_address

    def test_modify_strategy_params(self, avs_registry_writer):
        # Setup test data
        mock_quorum_number = Mock()
        mock_quorum_number.underlying_type.return_value = 2

        strategy_indices = [0, 1, 3]  # Indices of strategies to modify
        multipliers = [
            5000,
            7500,
            12000,
        ]  # New multipliers in basis points (50%, 75%, 120%)

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.stake_registry.functions.modifyStrategyParams.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.modify_strategy_params(
            quorum_number=mock_quorum_number,
            strategy_indices=strategy_indices,
            multipliers=multipliers,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.stake_registry.functions.modifyStrategyParams.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            2,  # underlying_type() return value
            strategy_indices,
            multipliers,
        )

        # Verify quorum_number.underlying_type() was called
        mock_quorum_number.underlying_type.assert_called_once()

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains quorum number
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "modifying strategy params for quorum" in log_call[0][0]
        assert log_call[1]["extra"]["quorumNumber"] == mock_quorum_number

    def test_set_account_identifier(self, avs_registry_writer):
        # Setup test data
        account_identifier_address = "0xAccountIdentifierAddress"

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.setAccountIdentifier.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_account_identifier(
            account_identifier_address=account_identifier_address, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.setAccountIdentifier.assert_called_once_with(
            {"from": "0x1234"}, account_identifier_address  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains account identifier address
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting account identifier" in log_call[0][0]
        assert log_call[1]["extra"]["accountIdentifierAddress"] == account_identifier_address

    def test_set_ejection_cooldown(self, avs_registry_writer):
        # Setup test data
        ejection_cooldown = 86400  # 1 day in seconds

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.registry_coordinator.functions.setEjectionCooldown.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.set_ejection_cooldown(
            ejection_cooldown=ejection_cooldown, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.registry_coordinator.functions.setEjectionCooldown.assert_called_once_with(
            {"from": "0x1234"}, ejection_cooldown  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains ejection cooldown
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "setting ejection cooldown" in log_call[0][0]
        assert log_call[1]["extra"]["ejectionCooldown"] == ejection_cooldown

    def test_add_strategies(self, avs_registry_writer):
        # Setup test data
        mock_quorum_number = Mock()
        mock_quorum_number.underlying_type.return_value = 3

        strategy_params = [
            {
                "strategyAddress": "0xNewStrategy1Address",
                "multiplier": 8000,  # 80% in basis points
            },
            {
                "strategyAddress": "0xNewStrategy2Address",
                "multiplier": 6000,  # 60% in basis points
            },
        ]

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.stake_registry.functions.addStrategies.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.add_strategies(
            quorum_number=mock_quorum_number,
            strategy_params=strategy_params,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.stake_registry.functions.addStrategies.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            3,  # underlying_type() return value
            strategy_params,
        )

        # Verify quorum_number.underlying_type() was called
        mock_quorum_number.underlying_type.assert_called()

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains quorum number
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "adding strategies for quorum" in log_call[0][0]
        assert log_call[1]["extra"]["quorumNumber"] == 3

    def test_update_avs_metadata_uri(self, avs_registry_writer):
        # Setup test data
        metadata_uri = "ipfs://QmExample123456789"

        # Setup mock service manager contract
        mock_service_manager_contract = Mock()
        mock_service_manager_contract.functions.updateAVSMetadataURI.return_value.build_transaction.return_value = {
            "gas": 1000000
        }

        # Setup web3.eth.contract to return the mock service manager contract
        avs_registry_writer.web3.eth.contract.return_value = mock_service_manager_contract

        # Add service_manager_abi attribute which is used in the method
        avs_registry_writer.service_manager_abi = "mock_service_manager_abi"

        # Call the function
        result = avs_registry_writer.update_avs_metadata_uri(
            metadata_uri=metadata_uri, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify contract was created correctly
        avs_registry_writer.web3.eth.contract.assert_called_once_with(
            address=avs_registry_writer.service_manager_addr,
            abi=avs_registry_writer.service_manager_abi,
        )

        # Verify transaction was built correctly
        mock_service_manager_contract.functions.updateAVSMetadataURI.assert_called_once_with(
            {"from": "0x1234"}, metadata_uri  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with({"gas": 1000000}, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains metadata URI
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "updating AVS metadata URI" in log_call[0][0]
        assert log_call[1]["extra"]["metadataUri"] == metadata_uri

    def test_remove_strategies(self, avs_registry_writer):
        # Setup test data
        mock_quorum_number = Mock()
        mock_quorum_number.underlying_type.return_value = 4

        indices_to_remove = [1, 3, 5]  # Indices of strategies to remove

        # Setup transaction mocks
        mock_tx = {"gas": 1000000}
        avs_registry_writer.stake_registry.functions.removeStrategies.return_value.build_transaction.return_value = (
            mock_tx
        )

        # Call the function
        result = avs_registry_writer.remove_strategies(
            quorum_number=mock_quorum_number,
            indices_to_remove=indices_to_remove,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify transaction was built correctly
        avs_registry_writer.stake_registry.functions.removeStrategies.assert_called_once_with(
            {"from": "0x1234"},  # tx_opts
            4,  # underlying_type() return value
            indices_to_remove,
        )

        # Verify quorum_number.underlying_type() was called
        mock_quorum_number.underlying_type.assert_called_once()

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with(mock_tx, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains quorum number
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "removing strategies from quorum" in log_call[0][0]
        assert log_call[1]["extra"]["quorumNumber"] == mock_quorum_number

    def test_create_avs_rewards_submission(self, avs_registry_writer):
        # Setup test data - rewards submission with operator rewards
        rewards_submission = [
            {
                "operatorId": "0x1234567890123456789012345678901234567890123456789012345678901234",
                "amount": 1000000000000000000,  # 1 ETH in wei
                "quorumNumber": 2,
            },
            {
                "operatorId": "0x2345678901234567890123456789012345678901234567890123456789012345",
                "amount": 2000000000000000000,  # 2 ETH in wei
                "quorumNumber": 3,
            },
        ]

        # Setup mock service manager contract
        mock_service_manager_contract = Mock()
        mock_service_manager_contract.functions.createAVSRewardsSubmission.return_value.build_transaction.return_value = {
            "gas": 1000000
        }

        # Setup web3.eth.contract to return the mock service manager contract
        avs_registry_writer.web3.eth.contract.return_value = mock_service_manager_contract

        # Add service_manager_abi attribute which is used in the method
        avs_registry_writer.service_manager_abi = "mock_service_manager_abi"

        # Call the function
        result = avs_registry_writer.create_avs_rewards_submission(
            rewards_submission=rewards_submission, wait_for_receipt=True
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify contract was created correctly
        avs_registry_writer.web3.eth.contract.assert_called_once_with(
            address=avs_registry_writer.service_manager_addr,
            abi=avs_registry_writer.service_manager_abi,
        )

        # Verify transaction was built correctly
        mock_service_manager_contract.functions.createAVSRewardsSubmission.assert_called_once_with(
            {"from": "0x1234"}, rewards_submission  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with({"gas": 1000000}, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains rewards submission data
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "creating AVS rewards submission" in log_call[0][0]
        assert log_call[1]["extra"]["rewardsSubmission"] == rewards_submission

    def test_create_operator_directed_avs_rewards_submission(self, avs_registry_writer):
        # Setup test data - operator directed rewards submission
        operator_directed_rewards_submissions = [
            {
                "operatorId": "0x1234567890123456789012345678901234567890123456789012345678901234",
                "rewards": [
                    {
                        "recipient": "0xRecipient1Address",
                        "amount": 500000000000000000,  # 0.5 ETH in wei
                    },
                    {
                        "recipient": "0xRecipient2Address",
                        "amount": 1500000000000000000,  # 1.5 ETH in wei
                    },
                ],
            },
            {
                "operatorId": "0x2345678901234567890123456789012345678901234567890123456789012345",
                "rewards": [
                    {
                        "recipient": "0xRecipient3Address",
                        "amount": 2000000000000000000,  # 2 ETH in wei
                    }
                ],
            },
        ]

        # Setup mock service manager contract
        mock_service_manager_contract = Mock()
        mock_service_manager_contract.functions.createOperatorDirectedAVSRewardsSubmission.return_value.build_transaction.return_value = {
            "gas": 1000000
        }

        # Setup web3.eth.contract to return the mock service manager contract
        avs_registry_writer.web3.eth.contract.return_value = mock_service_manager_contract

        # Add service_manager_abi attribute which is used in the method
        avs_registry_writer.service_manager_abi = "mock_service_manager_abi"

        # Call the function
        result = avs_registry_writer.create_operator_directed_avs_rewards_submission(
            operator_directed_rewards_submissions=operator_directed_rewards_submissions,
            wait_for_receipt=True,
        )

        # Assertions
        assert result == {"transactionHash": b"0x1234"}

        # Verify contract was created correctly
        avs_registry_writer.web3.eth.contract.assert_called_once_with(
            address=avs_registry_writer.service_manager_addr,
            abi=avs_registry_writer.service_manager_abi,
        )

        # Verify transaction was built correctly
        mock_service_manager_contract.functions.createOperatorDirectedAVSRewardsSubmission.assert_called_once_with(
            {"from": "0x1234"}, operator_directed_rewards_submissions  # tx_opts
        )

        # Verify transaction was sent
        avs_registry_writer.tx_mgr.send.assert_called_once_with({"gas": 1000000}, True)

        # Verify logging happened
        assert avs_registry_writer.logger.info.call_count == 1

        # Verify the log contains operator directed rewards submissions data
        log_call = avs_registry_writer.logger.info.call_args_list[0]
        assert "creating operator directed AVS rewards submission" in log_call[0][0]
        assert (
            log_call[1]["extra"]["operatorDirectedRewardsSubmissions"]
            == operator_directed_rewards_submissions
        )
