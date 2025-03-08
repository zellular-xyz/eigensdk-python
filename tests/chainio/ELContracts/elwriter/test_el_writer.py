from base import *
import pytest
from web3 import Web3
from unittest.mock import MagicMock

def test_register_as_operator(mocker):
    """Test the register_as_operator function in el_writer"""
    
    # Mock operator data
    operator = MagicMock()
    operator.address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    operator.delegation_approver_address = "0xd5e099c71b797516c10ed0f0d895f429c2781142"
    operator.allocation_delay = 0
    operator.metadata_url = "https://madhur-test-public.s3.us-east-2.amazonaws.com/metadata.json"

    # Case 1: If delegation_manager is None, it should raise an exception
    original_delegation_manager = el_writer.delegation_manager
    el_writer.delegation_manager = None
    
    with pytest.raises(ValueError, match="DelegationManager contract not provided"):
        el_writer.register_as_operator(operator, wait_for_receipt=True)
    
    # Restore the original delegation_manager
    el_writer.delegation_manager = original_delegation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator.address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    mock_register = mocker.patch.object(
        el_writer.delegation_manager.functions.registerAsOperator.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.register_as_operator(operator, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    el_writer.logger.info.assert_any_call(f"Registering operator {operator.address} to EigenLayer")
    el_writer.logger.info.assert_any_call(f"Transaction successfully included: txHash {receipt['transactionHash'].hex()}")
    mock_register.assert_called_once()


def test_update_operator_details(mocker):
    """Test the update_operator_details function in el_writer"""

    # Mock operator data
    operator = MagicMock()
    operator.address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    operator.delegation_approver_address = "0xd5e099c71b797516c10ed0f0d895f429c2781142"

    # Case 1: If delegation_manager is None, it should raise an exception
    original_delegation_manager = el_writer.delegation_manager
    el_writer.delegation_manager = None
    
    with pytest.raises(ValueError, match="DelegationManager contract not provided"):
        el_writer.update_operator_details(operator, wait_for_receipt=True)
    
    # Restore the original delegation_manager
    el_writer.delegation_manager = original_delegation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator.address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    mock_modify_operator = mocker.patch.object(
        el_writer.delegation_manager.functions.modifyOperatorDetails.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.update_operator_details(operator, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    el_writer.logger.info.assert_any_call(f"Updating operator details of operator {operator.address} to EigenLayer")
    el_writer.logger.info.assert_any_call(f"Successfully updated operator details | txHash: {receipt['transactionHash'].hex()} | operator: {operator.address}")
    mock_modify_operator.assert_called_once()


def test_update_metadata_uri(mocker):
    """Test the update_metadata_uri function in el_writer"""

    # Mock operator data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    metadata_uri = "https://example.com/metadata.json"

    # Case 1: If delegation_manager is None, it should raise an exception
    original_delegation_manager = el_writer.delegation_manager
    el_writer.delegation_manager = None
    
    with pytest.raises(ValueError, match="DelegationManager contract not provided"):
        el_writer.update_metadata_uri(operator_address, metadata_uri, wait_for_receipt=True)
    
    # Restore the original delegation_manager
    el_writer.delegation_manager = original_delegation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    mock_update_metadata = mocker.patch.object(
        el_writer.delegation_manager.functions.updateOperatorMetadataURI.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.update_metadata_uri(operator_address, metadata_uri, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    el_writer.logger.info.assert_any_call(f"Successfully updated operator metadata URI | txHash: {receipt['transactionHash'].hex()}")
    mock_update_metadata.assert_called_once()


def test_deposit_erc20_into_strategy(mocker):
    """Test the deposit_erc20_into_strategy function in el_writer"""

    # Mock strategy and amount
    strategy_addr = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
    amount = 1000

    # Case 1: If strategy_manager is None, it should raise an exception
    original_strategy_manager = el_writer.strategy_manager
    el_writer.strategy_manager = None

    with pytest.raises(ValueError, match="StrategyManager contract not provided"):
        el_writer.deposit_erc20_into_strategy(strategy_addr, amount, wait_for_receipt=True)

    # Restore the original strategy_manager
    el_writer.strategy_manager = original_strategy_manager

    # Case 2: Successful deposit
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": strategy_addr})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock el_chain_reader response
    underlying_token_contract = mocker.Mock()
    underlying_token_addr = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
    mocker.patch.object(
        el_writer.el_chain_reader,
        "get_strategy_and_underlying_erc20_token",
        return_value=(None, underlying_token_contract, underlying_token_addr),
    )

    # Mock approval transaction
    mock_approve_tx = mocker.patch.object(
        underlying_token_contract.functions.approve.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Mock deposit transaction
    mock_deposit_tx = mocker.patch.object(
        el_writer.strategy_manager.functions.depositIntoStrategy.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.deposit_erc20_into_strategy(strategy_addr, amount, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    el_writer.logger.info.assert_any_call(f"Depositing {amount} tokens into strategy {strategy_addr}")
    el_writer.logger.info.assert_any_call(f"Deposited {amount} into strategy {strategy_addr}")
    mock_approve_tx.assert_called_once()
    mock_deposit_tx.assert_called_once()


def test_set_claimer_for(mocker):
    """Test the set_claimer_for function in el_writer"""

    # Mock claimer address
    claimer_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.set_claimer_for(claimer_address, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": claimer_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_set_claimer_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.setClaimerFor.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.set_claimer_for(claimer_address, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_set_claimer_tx.assert_called_once()


def test_process_claim(mocker):
    """Test the process_claim function in el_writer"""

    # Mock claim data
    claim_data = {"amount": 1000, "token": "0x1234567890abcdef1234567890abcdef12345678"}
    recipient_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.process_claim(claim_data, recipient_address, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": recipient_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_process_claim_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.processClaim.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.process_claim(claim_data, recipient_address, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_process_claim_tx.assert_called_once()


def test_set_operator_avs_split(mocker):
    """Test the set_operator_avs_split function in el_writer"""

    # Mock operator and AVS data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    avs_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
    split = 50  # Example split value

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.set_operator_avs_split(operator_address, avs_address, split, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_set_operator_avs_split_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.setOperatorAVSSplit.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.set_operator_avs_split(operator_address, avs_address, split, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_set_operator_avs_split_tx.assert_called_once()


def test_set_operator_pi_split(mocker):
    """Test the set_operator_pi_split function in el_writer"""

    # Mock operator data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    split = 30  # Example split value

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.set_operator_pi_split(operator_address, split, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_set_operator_pi_split_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.setOperatorPISplit.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.set_operator_pi_split(operator_address, split, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_set_operator_pi_split_tx.assert_called_once()


def test_set_operator_set_split(mocker):
    """Test the set_operator_set_split function in el_writer"""

    # Mock operator data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    operator_set = {"members": ["0x1234567890abcdef1234567890abcdef12345678"]}
    split = 40  # Example split value

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.set_operator_set_split(operator_address, operator_set, split, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_set_operator_set_split_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.setOperatorSetSplit.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.set_operator_set_split(operator_address, operator_set, split, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_set_operator_set_split_tx.assert_called_once()


def test_process_claims(mocker):
    """Test the process_claims function in el_writer"""

    # Mock claims data
    claims_data = [{"amount": 1000, "token": "0x1234567890abcdef1234567890abcdef12345678"}]
    recipient_address = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"

    # Case 1: If rewards_coordinator is None, it should raise an exception
    original_rewards_coordinator = el_writer.rewards_coordinator
    el_writer.rewards_coordinator = None

    with pytest.raises(ValueError, match="RewardsCoordinator contract not provided"):
        el_writer.process_claims(claims_data, recipient_address, wait_for_receipt=True)

    # Restore the original rewards_coordinator
    el_writer.rewards_coordinator = original_rewards_coordinator

    # Case 2: If claims list is empty, it should raise an exception
    with pytest.raises(ValueError, match="Claims list is empty, at least one claim must be provided"):
        el_writer.process_claims([], recipient_address, wait_for_receipt=True)

    # Case 3: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": recipient_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_process_claims_tx = mocker.patch.object(
        el_writer.rewards_coordinator.functions.processClaims.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.process_claims(claims_data, recipient_address, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_process_claims_tx.assert_called_once()


def test_modify_allocations(mocker):
    """Test the modify_allocations function in el_writer"""

    # Mock operator and allocations data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    allocations = [{"strategy": "0x1234567890abcdef1234567890abcdef12345678", "amount": 1000}]

    # Case 1: If allocation_manager is None, it should raise an exception
    original_allocation_manager = el_writer.allocation_manager
    el_writer.allocation_manager = None

    with pytest.raises(ValueError, match="AllocationManager contract not provided"):
        el_writer.modify_allocations(operator_address, allocations, wait_for_receipt=True)

    # Restore the original allocation_manager
    el_writer.allocation_manager = original_allocation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_modify_allocations_tx = mocker.patch.object(
        el_writer.allocation_manager.functions.modifyAllocations.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.modify_allocations(operator_address, allocations, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_modify_allocations_tx.assert_called_once()


def test_clear_deallocation_queue(mocker):
    """Test the clear_deallocation_queue function in el_writer"""

    # Mock operator and strategies data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    strategies = [
        "0x1234567890abcdef1234567890abcdef12345678",
        "0xabcdef1234567890abcdef1234567890abcdef12"
    ]
    nums_to_clear = [1, 2]  # Example number of deallocations to clear

    # Case 1: If allocation_manager is None, it should raise an exception
    original_allocation_manager = el_writer.allocation_manager
    el_writer.allocation_manager = None

    with pytest.raises(ValueError, match="AllocationManager contract not provided"):
        el_writer.clear_deallocation_queue(operator_address, strategies, nums_to_clear, wait_for_receipt=True)

    # Restore the original allocation_manager
    el_writer.allocation_manager = original_allocation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_clear_deallocation_tx = mocker.patch.object(
        el_writer.allocation_manager.functions.clearDeallocationQueue.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.clear_deallocation_queue(operator_address, strategies, nums_to_clear, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_clear_deallocation_tx.assert_called_once()


def test_set_allocation_delay(mocker):
    """Test the set_allocation_delay function in el_writer"""

    # Mock operator data
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    delay = 3600  # Example delay in seconds

    # Case 1: If allocation_manager is None, it should raise an exception
    original_allocation_manager = el_writer.allocation_manager
    el_writer.allocation_manager = None

    with pytest.raises(ValueError, match="AllocationManager contract not provided"):
        el_writer.set_allocation_delay(operator_address, delay, wait_for_receipt=True)

    # Restore the original allocation_manager
    el_writer.allocation_manager = original_allocation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_set_allocation_delay_tx = mocker.patch.object(
        el_writer.allocation_manager.functions.setAllocationDelay.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.set_allocation_delay(operator_address, delay, wait_for_receipt=True)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_set_allocation_delay_tx.assert_called_once()


def test_deregister_from_operator_sets(mocker):
    """Test the deregister_from_operator_sets function in el_writer"""

    # Mock operator data and request parameters
    operator_address = "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    request_data = {
        "avs_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "operator_set_ids": [1, 2, 3],
        "wait_for_receipt": True
    }

    # Case 1: If allocation_manager is None, it should raise an exception
    original_allocation_manager = el_writer.allocation_manager
    el_writer.allocation_manager = None

    with pytest.raises(ValueError, match="AllocationManager contract not provided"):
        el_writer.deregister_from_operator_sets(operator_address, request_data)

    # Restore the original allocation_manager
    el_writer.allocation_manager = original_allocation_manager

    # Case 2: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": operator_address})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_deregister_tx = mocker.patch.object(
        el_writer.allocation_manager.functions.deregisterFromOperatorSets.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.deregister_from_operator_sets(operator_address, request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_deregister_tx.assert_called_once()


def test_register_for_operator_sets(mocker):
    """Test the register_for_operator_sets function in el_writer"""

    # Mock registry coordinator and request parameters
    registry_coordinator_address = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
    request_data = {
        "operator_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "avs_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "operator_set_ids": [1, 2, 3],
        "bls_key_pair": {"public": "some_pub_key", "private": "some_priv_key"},
        "socket": "some_socket_data",
        "wait_for_receipt": True
    }

    # Case 1: If allocation_manager is None, it should raise an exception
    original_allocation_manager = el_writer.allocation_manager
    el_writer.allocation_manager = None

    with pytest.raises(ValueError, match="AllocationManager contract not provided"):
        el_writer.register_for_operator_sets(registry_coordinator_address, request_data)

    # Restore the original allocation_manager
    el_writer.allocation_manager = original_allocation_manager

    # Case 2: Mock public key registration params and ABI encoding
    mocker.patch("eigensdk.some_module.get_pubkey_registration_params", return_value="mock_pubkey_params")
    mocker.patch("eigensdk.some_module.abi_encode_registration_params", return_value="mock_encoded_data")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["operator_address"]})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    # Mock contract transaction
    mock_register_tx = mocker.patch.object(
        el_writer.allocation_manager.functions.registerForOperatorSets.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    # Call function
    receipt = el_writer.register_for_operator_sets(registry_coordinator_address, request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt
    mock_register_tx.assert_called_once()


def test_remove_permission(mocker):
    """Test the remove_permission function in el_writer"""

    # Mock request parameters
    request_data = {
        "operator_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "permission_id": "0xabcdef1234567890abcdef1234567890abcdef12",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.remove_permission(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["operator_address"]})
    mocker.patch.object(el_writer, "new_remove_permission_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.remove_permission(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewRemovePermissionTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_remove_permission_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.remove_permission(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_new_remove_permission_tx(mocker):
    """Test the new_remove_permission_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "appointee_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "target": "some_target",
        "selector": "some_selector",
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_remove_permission_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_remove_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removeAppointee.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_remove_permission_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewRemovePermissionTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_remove_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removeAppointee.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_remove_permission_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_remove_tx.assert_called_once()


def test_new_set_permission_tx(mocker):
    """Test the new_set_permission_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "appointee_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "target": "some_target",
        "selector": "some_selector",
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_set_permission_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_set_tx = mocker.patch.object(
        el_writer.permission_controller.functions.setAppointee.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_set_permission_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewSetPermissionTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_set_tx = mocker.patch.object(
        el_writer.permission_controller.functions.setAppointee.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_set_permission_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_set_tx.assert_called_once()


def test_set_permission(mocker):
    """Test the set_permission function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "appointee_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "target": "some_target",
        "selector": "some_selector",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.set_permission(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["account_address"]})
    mocker.patch.object(el_writer, "new_set_permission_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.set_permission(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewSetPermissionTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_set_permission_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.set_permission(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_new_accept_admin_tx(mocker):
    """Test the new_accept_admin_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1"
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_accept_admin_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_accept_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.acceptAdmin.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_accept_admin_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewAcceptAdminTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_accept_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.acceptAdmin.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_accept_admin_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_accept_admin_tx.assert_called_once()


def test_accept_admin(mocker):
    """Test the accept_admin function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.accept_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["account_address"]})
    mocker.patch.object(el_writer, "new_accept_admin_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.accept_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create AcceptAdmin transaction: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_accept_admin_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.accept_admin(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_add_pending_admin(mocker):
    """Test the add_pending_admin function in el_writer"""

    # Mock request parameters
    request_data = {
        "admin_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.add_pending_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["admin_address"]})
    mocker.patch.object(el_writer, "new_add_pending_admin_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.add_pending_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create AddPendingAdminTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_add_pending_admin_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.add_pending_admin(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_new_remove_admin_tx(mocker):
    """Test the new_remove_admin_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "admin_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_remove_admin_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_remove_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removeAdmin.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_remove_admin_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewRemoveAdminTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_remove_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removeAdmin.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_remove_admin_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_remove_admin_tx.assert_called_once()


def test_remove_admin(mocker):
    """Test the remove_admin function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "admin_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.remove_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["account_address"]})
    mocker.patch.object(el_writer, "new_remove_admin_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.remove_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create RemoveAdmin transaction: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_remove_admin_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.remove_admin(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_new_remove_pending_admin_tx(mocker):
    """Test the new_remove_pending_admin_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "admin_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_remove_pending_admin_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_remove_pending_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removePendingAdmin.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_remove_pending_admin_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewRemovePendingAdminTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_remove_pending_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.removePendingAdmin.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_remove_pending_admin_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_remove_pending_admin_tx.assert_called_once()\


def test_remove_pending_admin(mocker):
    """Test the remove_pending_admin function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "admin_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
        "wait_for_receipt": True
    }

    # Case 1: Failure in getting transaction options
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", side_effect=Exception("Failed to get no-send tx opts"))

    receipt, error = el_writer.remove_pending_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to get no-send tx opts"
    el_writer.logger.error.assert_called_with("Failed to get no-send tx opts: %s", "Failed to get no-send tx opts")

    # Case 2: Failure in transaction creation
    mocker.patch.object(el_writer.tx_mgr, "get_no_send_tx_opts", return_value={"from": request_data["account_address"]})
    mocker.patch.object(el_writer, "new_remove_pending_admin_tx", side_effect=Exception("Failed to create transaction"))

    receipt, error = el_writer.remove_pending_admin(request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create RemovePendingAdmin transaction: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mocker.patch.object(el_writer, "new_remove_pending_admin_tx", return_value={"mock_tx": "tx_data"})
    mocker.patch.object(el_writer.tx_mgr, "send", return_value={"transactionHash": b"\x12\x34\x56"})

    receipt = el_writer.remove_pending_admin(request_data)

    # Assertions for success case
    assert receipt is not None
    assert "transactionHash" in receipt


def test_new_add_pending_admin_tx(mocker):
    """Test the new_add_pending_admin_tx function in el_writer"""

    # Mock request parameters
    request_data = {
        "account_address": "0x408EfD9C90d59298A9b32F4441aC9Df6A2d8C3E1",
        "admin_address": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
    }

    # Mock transaction options
    tx_opts = {"from": request_data["account_address"]}

    # Case 1: If permission_controller is None, it should raise an exception
    original_permission_controller = el_writer.permission_controller
    el_writer.permission_controller = None

    with pytest.raises(ValueError, match="Permission contract not provided"):
        el_writer.new_add_pending_admin_tx(tx_opts, request_data)

    # Restore the original permission_controller
    el_writer.permission_controller = original_permission_controller

    # Case 2: Failure in transaction creation
    mock_add_pending_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.addPendingAdmin.return_value,
        "build_transaction",
        side_effect=Exception("Failed to create transaction")
    )

    receipt, error = el_writer.new_add_pending_admin_tx(tx_opts, request_data)
    assert receipt is None
    assert str(error) == "Failed to create transaction"
    el_writer.logger.error.assert_called_with("Failed to create NewAddPendingAdminTx: %s", "Failed to create transaction")

    # Case 3: Successful transaction
    mock_add_pending_admin_tx = mocker.patch.object(
        el_writer.permission_controller.functions.addPendingAdmin.return_value,
        "build_transaction",
        return_value={"mock_tx": "tx_data"},
    )

    tx = el_writer.new_add_pending_admin_tx(tx_opts, request_data)

    # Assertions for success case
    assert tx is not None
    assert "mock_tx" in tx
    mock_add_pending_admin_tx.assert_called_once()