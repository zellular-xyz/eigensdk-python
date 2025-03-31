import pytest
from unittest.mock import MagicMock, patch
from tests.builder import *
from eigensdk.chainio.chainio_utils.utils import abi_encode_registration_params
from web3 import Web3


@pytest.fixture
def mock_operator():
    """Mock Operator Object"""
    return type(
        "Operator",
        (object,),
        {
            "address": "0x1234567890abcdef1234567890abcdef12345678",
            "delegation_approver_address": "0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            "allocation_delay": 100,
            "metadata_url": "https://example.com/metadata.json",
        },
    )()


@pytest.fixture
def mock_tx_manager():
    """Mock TxManager"""
    mock_tx_mgr = MagicMock()
    mock_tx_mgr.get_no_send_tx_opts.return_value = {
        "gas": 21000,
        "gasPrice": 1000000000,
    }
    mock_tx_mgr.send.return_value = MagicMock(transactionHash=MagicMock(hex=lambda: "0xabc123"))
    return mock_tx_mgr


@pytest.fixture
def mock_el_writer(mock_tx_manager):
    """Mock the el_writer object"""
    el_writer.tx_mgr = mock_tx_manager  # ✅ Ensure tx_mgr is mocked
    el_writer.logger = MagicMock()  # ✅ Mock logger to prevent logging issues
    el_writer.delegation_manager = MagicMock()  # ✅ Mock delegation_manager
    return el_writer


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, delegation_manager_mock, expected_exception, expected_message",
    [
        (
            "success",
            None,
            MagicMock(),
            None,
            "Transaction successfully included: txHash 0xabc123",
        ),
    ],
)
def test_register_as_operator(
    mock_el_writer,
    mock_operator,
    test_scenario,
    tx_manager_side_effect,
    delegation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for register_as_operator in one function."""

    # Setup the scenario
    if test_scenario == "success":
        mock_el_writer.delegation_manager = delegation_manager_mock
        mock_el_writer.delegation_manager.functions.registerAsOperator.return_value.build_transaction.return_value = {
            "to": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    elif test_scenario == "no_contract":
        original_delegation_manager = mock_el_writer.delegation_manager
        mock_el_writer.delegation_manager = delegation_manager_mock  # None

    elif test_scenario == "tx_fail":
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect

    # Run the test and validate behavior
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.register_as_operator(mock_operator, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.register_as_operator(mock_operator, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            mock_el_writer.logger.info.assert_called_with(expected_message)
        elif test_scenario == "tx_fail":
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert str(receipt[1]) == expected_message  # ✅ Check the error message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, delegation_manager_mock, expected_exception, expected_message",
    [
        (
            "success",
            None,
            MagicMock(),
            None,
            "Successfully updated operator details | txHash: 0xabc123 | operator: 0x1234567890abcdef1234567890abcdef12345678",
        ),
    ],
)
def test_update_operator_details(
    mock_el_writer,
    mock_operator,
    test_scenario,
    tx_manager_side_effect,
    delegation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for update_operator_details in one function."""

    # Setup the scenario
    if test_scenario == "success":
        mock_el_writer.delegation_manager = delegation_manager_mock
        mock_el_writer.delegation_manager.functions.modifyOperatorDetails.return_value.build_transaction.return_value = {
            "to": "0x123",
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    elif test_scenario == "no_contract":
        mock_el_writer.delegation_manager = delegation_manager_mock  # None

    elif test_scenario == "tx_fail":
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect

    # Run the test and validate behavior
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.update_operator_details(mock_operator, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.update_operator_details(mock_operator, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            mock_el_writer.logger.info.assert_called_with(expected_message)
        elif test_scenario == "tx_fail":
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert str(receipt[1]) == expected_message  # ✅ Check the error message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, delegation_manager_mock, expected_exception, expected_message",
    [
        (
            "success",
            None,
            MagicMock(),
            None,
            "Successfully updated operator metadata URI | txHash: 0xabc123",
        ),
    ],
)
def test_update_metadata_uri(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    delegation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for update_metadata_uri in one function."""

    operator_address = "0x1234567890abcdef1234567890abcdef12345678"
    uri = "https://example.com/metadata.json"

    # Setup the scenario
    if test_scenario == "success":
        mock_el_writer.delegation_manager = delegation_manager_mock
        mock_el_writer.delegation_manager.functions.updateOperatorMetadataURI.return_value.build_transaction.return_value = {
            "to": operator_address,
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    elif test_scenario == "no_contract":
        mock_el_writer.delegation_manager = delegation_manager_mock  # None

    elif test_scenario == "tx_fail":
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect

    # Run the test and validate behavior
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.update_metadata_uri(operator_address, uri, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.update_metadata_uri(operator_address, uri, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            mock_el_writer.logger.info.assert_called_with(expected_message)
        elif test_scenario == "tx_fail":
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert str(receipt[1]) == expected_message  # ✅ Check the error message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_set_claimer_for(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_claimer_for function."""

    claimer_address = "0x1234567890abcdef1234567890abcdef12345678"

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.setClaimerFor.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.setClaimerFor.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.setClaimerFor.return_value.build_transaction.return_value = {
                "to": claimer_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.set_claimer_for(claimer_address, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.set_claimer_for(claimer_address, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert str(receipt[1]) == expected_message  # ✅ Check the error message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_log_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_process_claim(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_log_message,
):
    """Test multiple scenarios for process_claim function."""

    claim_data = {"amount": 1000, "nonce": 12345}
    recipient_address = "0x1234567890abcdef1234567890abcdef12345678"

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.processClaim.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.processClaim.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.processClaim.return_value.build_transaction.return_value = {
                "to": recipient_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.process_claim(claim_data, recipient_address, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.process_claim(claim_data, recipient_address, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_log_message in str(receipt[1])  # ✅ Check the logged message

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_log_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_set_operator_avs_split(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_operator_avs_split function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    avs_address = Web3.to_checksum_address(
        "0xABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"
    )  # ✅ Valid Address

    split_value = 50

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.setOperatorAVSSplit.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.setOperatorAVSSplit.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.setOperatorAVSSplit.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.set_operator_avs_split(
                operator_address, avs_address, split_value, wait_for_receipt=True
            )
    else:
        receipt = mock_el_writer.set_operator_avs_split(
            operator_address, avs_address, split_value, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_set_operator_pi_split(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_operator_pi_split function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    split_value = 25

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.setOperatorPISplit.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.setOperatorPISplit.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.setOperatorPISplit.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.set_operator_pi_split(
                operator_address, split_value, wait_for_receipt=True
            )
    else:
        receipt = mock_el_writer.set_operator_pi_split(
            operator_address, split_value, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_set_operator_set_split(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_operator_set_split function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    operator_set = {"key1": "value1", "key2": "value2"}
    split_value = 40

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.setOperatorSetSplit.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.setOperatorSetSplit.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.setOperatorSetSplit.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.set_operator_set_split(
                operator_address, operator_set, split_value, wait_for_receipt=True
            )
    else:
        receipt = mock_el_writer.set_operator_set_split(
            operator_address, operator_set, split_value, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, claims, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, rewards_coordinator_mock, expected_exception, expected_message",
    [
        (
            "success",
            [{"amount": 1000, "nonce": 12345}],
            None,
            None,
            None,
            MagicMock(),
            None,
            None,
        ),
    ],
)
def test_process_claims(
    mock_el_writer,
    test_scenario,
    claims,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    rewards_coordinator_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for process_claims function."""

    recipient_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock RewardsCoordinator contract
    if test_scenario == "no_rewards_coordinator":
        mock_el_writer.rewards_coordinator = None
    else:
        mock_el_writer.rewards_coordinator = rewards_coordinator_mock
        mock_el_writer.rewards_coordinator.functions.processClaims.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.rewards_coordinator.functions.processClaims.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.rewards_coordinator.functions.processClaims.return_value.build_transaction.return_value = {
                "to": recipient_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.process_claims(claims, recipient_address, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.process_claims(claims, recipient_address, wait_for_receipt=True)

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, allocation_manager_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_modify_allocations(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    allocation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for modify_allocations function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    allocations = [{"asset": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef", "amount": 1000}]

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock AllocationManager contract
    if test_scenario == "no_allocation_manager":
        mock_el_writer.allocation_manager = None
    else:
        mock_el_writer.allocation_manager = allocation_manager_mock
        mock_el_writer.allocation_manager.functions.modifyAllocations.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.allocation_manager.functions.modifyAllocations.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.allocation_manager.functions.modifyAllocations.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.modify_allocations(operator_address, allocations, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.modify_allocations(
            operator_address, allocations, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, allocation_manager_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_clear_deallocation_queue(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    allocation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for clear_deallocation_queue function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    strategies = [
        Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678"),
        Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345677"),
    ]
    nums_to_clear = [1, 2]

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock AllocationManager contract
    if test_scenario == "no_allocation_manager":
        mock_el_writer.allocation_manager = None
    else:
        mock_el_writer.allocation_manager = allocation_manager_mock
        mock_el_writer.allocation_manager.functions.clearDeallocationQueue.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.allocation_manager.functions.clearDeallocationQueue.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.allocation_manager.functions.clearDeallocationQueue.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.clear_deallocation_queue(
                operator_address, strategies, nums_to_clear, wait_for_receipt=True
            )
    else:
        receipt = mock_el_writer.clear_deallocation_queue(
            operator_address, strategies, nums_to_clear, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, allocation_manager_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_set_allocation_delay(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    allocation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_allocation_delay function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    delay = 3600  # Example delay in seconds

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock AllocationManager contract
    if test_scenario == "no_allocation_manager":
        mock_el_writer.allocation_manager = None
    else:
        mock_el_writer.allocation_manager = allocation_manager_mock
        mock_el_writer.allocation_manager.functions.setAllocationDelay.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.allocation_manager.functions.setAllocationDelay.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.allocation_manager.functions.setAllocationDelay.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.set_allocation_delay(operator_address, delay, wait_for_receipt=True)
    else:
        receipt = mock_el_writer.set_allocation_delay(
            operator_address, delay, wait_for_receipt=True
        )

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, allocation_manager_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_deregister_from_operator_sets(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    allocation_manager_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for deregister_from_operator_sets function."""

    operator_address = Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345678")
    request = {
        "avs_address": Web3.to_checksum_address("0x1234567890abcdef1234567890abcdef12345677"),
        "operator_set_ids": [1, 2, 3],
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock AllocationManager contract
    if test_scenario == "no_allocation_manager":
        mock_el_writer.allocation_manager = None
    else:
        mock_el_writer.allocation_manager = allocation_manager_mock
        mock_el_writer.allocation_manager.functions.deregisterFromOperatorSets.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.allocation_manager.functions.deregisterFromOperatorSets.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.allocation_manager.functions.deregisterFromOperatorSets.return_value.build_transaction.return_value = {
                "to": operator_address,
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.deregister_from_operator_sets(operator_address, request)
    else:
        receipt = mock_el_writer.deregister_from_operator_sets(operator_address, request)

        if test_scenario == "success":
            assert receipt is not None
            assert hasattr(receipt, "transactionHash")
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt is None or (receipt[0] is None and isinstance(receipt[1], Exception))
            assert expected_message in str(receipt[1])

            # **Check if expected error log was called**
            mock_el_writer.logger.error.assert_any_call(
                pytest.helpers.string_contains(expected_message)
            )


@pytest.mark.parametrize(
    "test_scenario, tx_opts_side_effect, build_tx_side_effect, send_tx_side_effect, expected_exception, expected_message",
    [
        ("success", None, None, None, None, None),
    ],
)
def test_remove_permission(
    mock_el_writer,
    test_scenario,
    tx_opts_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for remove_permission function."""

    request_data = {
        "some_key": "some_value",  # Adjust based on actual expected fields
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_opts_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_opts_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `new_remove_permission_tx`
    mock_el_writer.new_remove_permission_tx = MagicMock()
    if build_tx_side_effect:
        mock_el_writer.new_remove_permission_tx.side_effect = build_tx_side_effect
    else:
        mock_el_writer.new_remove_permission_tx.return_value = {
            "to": "0x1234567890abcdef1234567890abcdef12345678",
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.remove_permission(request_data)
    else:
        receipt = mock_el_writer.remove_permission(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, tx_opts_side_effect, new_tx_side_effect, send_tx_side_effect, expected_exception, expected_message",
    [
        ("success", None, None, None, None, None),
    ],
)
def test_set_permission(
    mock_el_writer,
    test_scenario,
    tx_opts_side_effect,
    new_tx_side_effect,
    send_tx_side_effect,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for set_permission function."""

    request_data = {
        "account_address": "0x1234567890abcdef1234567890abcdef12345678",
        "appointee_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
        "target": "0xTargetContract",
        "selector": "0xSelector",
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_opts_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_opts_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `new_set_permission_tx`
    mock_el_writer.new_set_permission_tx = MagicMock()
    if new_tx_side_effect:
        mock_el_writer.new_set_permission_tx.side_effect = new_tx_side_effect
    else:
        mock_el_writer.new_set_permission_tx.return_value = {
            "to": request_data["account_address"],
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.set_permission(request_data)
    else:
        receipt = mock_el_writer.set_permission(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "new_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, permission_controller_mock, build_tx_side_effect, expected_exception, expected_message",
    [
        ("success", MagicMock(), None, None, None),
    ],
)
def test_new_accept_admin_tx(
    mock_el_writer,
    test_scenario,
    permission_controller_mock,
    build_tx_side_effect,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for new_accept_admin_tx function."""

    request_data = {
        "account_address": "0x1234567890abcdef1234567890abcdef12345678",
    }

    tx_opts = {"gas": 21000, "gasPrice": 1000000000}

    # Mock permission_controller
    if test_scenario == "no_permission_controller":
        mock_el_writer.permission_controller = None
    else:
        mock_el_writer.permission_controller = permission_controller_mock
        mock_el_writer.permission_controller.functions.acceptAdmin.return_value.build_transaction = (
            MagicMock()
        )

        if build_tx_side_effect:
            mock_el_writer.permission_controller.functions.acceptAdmin.return_value.build_transaction.side_effect = (
                build_tx_side_effect
            )
        else:
            mock_el_writer.permission_controller.functions.acceptAdmin.return_value.build_transaction.return_value = {
                "to": request_data["account_address"],
                "gas": 21000,
                "gasPrice": 1000000000,
            }

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.new_accept_admin_tx(tx_opts, request_data)
    else:
        tx = mock_el_writer.new_accept_admin_tx(tx_opts, request_data)

        if test_scenario == "success":
            assert tx is not None
            assert tx["to"] == request_data["account_address"]
        elif test_scenario == "build_tx_fail":
            assert tx[0] is None  # ✅ Ensure first item is None
            assert isinstance(tx[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(tx[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, tx_opts_side_effect, new_tx_side_effect, send_tx_side_effect, expected_exception, expected_message",
    [
        ("success", None, None, None, None, None),
    ],
)
def test_accept_admin(
    mock_el_writer,
    test_scenario,
    tx_opts_side_effect,
    new_tx_side_effect,
    send_tx_side_effect,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for accept_admin function."""

    request_data = {
        "account_address": "0x1234567890abcdef1234567890abcdef12345678",
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_opts_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_opts_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `new_accept_admin_tx`
    mock_el_writer.new_accept_admin_tx = MagicMock()
    if new_tx_side_effect:
        mock_el_writer.new_accept_admin_tx.side_effect = new_tx_side_effect
    else:
        mock_el_writer.new_accept_admin_tx.return_value = {
            "to": request_data["account_address"],
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.accept_admin(request_data)
    else:
        receipt = mock_el_writer.accept_admin(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        else:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, tx_opts_side_effect, new_tx_side_effect, send_tx_side_effect, expected_exception, expected_message",
    [
        ("success", None, None, None, None, None),
    ],
)
def test_add_pending_admin(
    mock_el_writer,
    test_scenario,
    tx_opts_side_effect,
    new_tx_side_effect,
    send_tx_side_effect,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for add_pending_admin function."""

    request_data = {
        "admin_address": "0x1234567890abcdef1234567890abcdef12345678",
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_opts_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_opts_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `new_add_pending_admin_tx`
    mock_el_writer.new_add_pending_admin_tx = MagicMock()
    if new_tx_side_effect:
        mock_el_writer.new_add_pending_admin_tx.side_effect = new_tx_side_effect
    else:
        mock_el_writer.new_add_pending_admin_tx.return_value = {
            "to": request_data["admin_address"],
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception):
            mock_el_writer.add_pending_admin(request_data)
    else:
        receipt = mock_el_writer.add_pending_admin(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        else:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, permission_controller_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_remove_admin(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    permission_controller_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for remove_admin function."""

    request_data = {
        "account_address": "0x1234567890abcdef1234567890abcdef12345678",
        "admin_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock permission controller and transaction creation
    mock_el_writer.new_remove_admin_tx = MagicMock()
    if build_tx_side_effect:
        mock_el_writer.new_remove_admin_tx.side_effect = build_tx_side_effect
    else:
        mock_el_writer.new_remove_admin_tx.return_value = {
            "to": request_data["account_address"],
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.remove_admin(request_data)
    else:
        receipt = mock_el_writer.remove_admin(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.mark.parametrize(
    "test_scenario, tx_manager_side_effect, build_tx_side_effect, send_tx_side_effect, permission_controller_mock, expected_exception, expected_message",
    [
        ("success", None, None, None, MagicMock(), None, None),
    ],
)
def test_remove_pending_admin(
    mock_el_writer,
    test_scenario,
    tx_manager_side_effect,
    build_tx_side_effect,
    send_tx_side_effect,
    permission_controller_mock,
    expected_exception,
    expected_message,
):
    """Test multiple scenarios for remove_pending_admin function."""

    request_data = {
        "account_address": "0x1234567890abcdef1234567890abcdef12345678",
        "admin_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
        "wait_for_receipt": True,
    }

    # Mock `get_no_send_tx_opts`
    mock_el_writer.tx_mgr.get_no_send_tx_opts = MagicMock()
    if tx_manager_side_effect:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.side_effect = tx_manager_side_effect
    else:
        mock_el_writer.tx_mgr.get_no_send_tx_opts.return_value = {
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `new_remove_pending_admin_tx`
    mock_el_writer.new_remove_pending_admin_tx = MagicMock()
    if build_tx_side_effect:
        mock_el_writer.new_remove_pending_admin_tx.side_effect = build_tx_side_effect
    else:
        mock_el_writer.new_remove_pending_admin_tx.return_value = {
            "to": request_data["account_address"],
            "gas": 21000,
            "gasPrice": 1000000000,
        }

    # Mock `send`
    mock_el_writer.tx_mgr.send = MagicMock()
    if send_tx_side_effect:
        mock_el_writer.tx_mgr.send.side_effect = send_tx_side_effect
    else:
        mock_el_writer.tx_mgr.send.return_value = MagicMock(
            transactionHash=MagicMock(hex=lambda: "0xabc123")
        )

    # Mock logger
    mock_el_writer.logger.error = MagicMock()

    # **Run the test and validate behavior**
    if expected_exception:
        with pytest.raises(expected_exception, match=expected_message):
            mock_el_writer.remove_pending_admin(request_data)
    else:
        receipt = mock_el_writer.remove_pending_admin(request_data)

        if test_scenario == "success":
            assert receipt is not None
            assert receipt.transactionHash.hex() == "0xabc123"
        elif test_scenario in ["tx_opts_fail", "build_tx_fail", "send_tx_fail"]:
            assert receipt[0] is None  # ✅ Ensure first item is None
            assert isinstance(receipt[1], Exception)  # ✅ Ensure second item is an exception
            assert expected_message in str(receipt[1])  # ✅ Check the logged message


@pytest.fixture
def strategy_address():
    return "0x09635F643e140090A9A8Dcd712eD6285858ceBef"


@pytest.fixture
def token_address():
    return "0x2222222222222222222222222222222222222222"


@pytest.fixture
def deposit_amount():
    return 1000000000000000000  # 1 token with 18 decimals


def test_deposit_erc20_into_strategy(
    mocker, mock_el_writer, strategy_address, token_address, deposit_amount
):
    """Test deposit_erc20_into_strategy function."""

    # Use a valid Ethereum address for strategy manager
    strategy_manager_address = "0x1111111111111111111111111111111111111111"

    # Mock the token contract and its approve function
    mock_token_contract = mocker.MagicMock()
    mock_approve_fn = mocker.MagicMock()
    mock_approve_fn.build_transaction.return_value = {
        "to": token_address,
        "data": "0xapprove_data",
        "gas": 21000,
        "gasPrice": 1000000000,
    }
    mock_token_contract.functions.approve.return_value = mock_approve_fn

    # Mock the strategy_manager and functions attribute properly
    mock_el_writer.strategy_manager = mocker.MagicMock()
    mock_el_writer.strategy_manager.address = strategy_manager_address
    mock_el_writer.strategy_manager.functions = mocker.MagicMock()

    # Set up the deposit function mock
    mock_deposit_fn = mocker.MagicMock()
    mock_deposit_fn.build_transaction.return_value = {
        "to": strategy_manager_address,
        "data": "0xdeposit_data",
        "gas": 21000,
        "gasPrice": 1000000000,
    }
    mock_el_writer.strategy_manager.functions.depositIntoStrategy = mocker.MagicMock(
        return_value=mock_deposit_fn
    )

    # Mock el_chain_reader's get_strategy_and_underlying_erc20_token
    mock_strategy_contract = mocker.MagicMock()
    mock_el_writer.el_chain_reader = mocker.MagicMock()
    mock_el_writer.el_chain_reader.get_strategy_and_underlying_erc20_token.return_value = (
        mock_strategy_contract,
        mock_token_contract,
        token_address,
    )

    # Mock transaction receipt
    mock_receipt = mocker.MagicMock()
    mock_receipt.transactionHash = mocker.MagicMock(hex=lambda: "0xabc123")

    # Mock the tx_mgr.send to return the receipt on the second call
    mock_el_writer.tx_mgr.send.side_effect = [(None, None), mock_receipt]

    # Call the method
    result = mock_el_writer.deposit_erc20_into_strategy(
        strategy_address, deposit_amount, wait_for_receipt=True
    )

    # Verify the el_chain_reader was called correctly
    mock_el_writer.el_chain_reader.get_strategy_and_underlying_erc20_token.assert_called_once_with(
        strategy_address
    )

    # Verify token approval was called correctly
    mock_token_contract.functions.approve.assert_called_once_with(
        Web3.to_checksum_address(strategy_manager_address), deposit_amount
    )

    # Verify deposit into strategy was called correctly
    mock_el_writer.strategy_manager.functions.depositIntoStrategy.assert_called_once_with(
        Web3.to_checksum_address(strategy_address),
        Web3.to_checksum_address(token_address),
        deposit_amount,
    )

    # Verify transaction sending
    assert mock_el_writer.tx_mgr.send.call_count == 2

    # Verify the result
    assert result == mock_receipt
    assert result.transactionHash.hex() == "0xabc123"

    # Verify logging occurred
    mock_el_writer.logger.info.assert_any_call(
        f"Depositing {deposit_amount} tokens into strategy {strategy_address}"
    )
    mock_el_writer.logger.info.assert_any_call(
        f"Deposited {deposit_amount} into strategy {strategy_address}"
    )
