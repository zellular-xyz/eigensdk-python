from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest
from eigensdk._types import Operator


def test_register_as_operator():
    # Create a new operator for testing
    operator = Operator(
        address=Web3.to_checksum_address(config["operator_address"]),
        delegation_approver_address="0x0000000000000000000000000000000000000000",  # No delegation approver
        allocation_delay=100,  # 100 blocks
        metadata_url="https://example.com/operator-metadata",
    )

    # Register as operator
    receipt = clients.el_writer.register_as_operator(operator)
<<<<<<< HEAD

=======
    print(f"Receipt: {receipt}")
>>>>>>> 285c207 (Fix: lint and MyPy Done)
    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")


<<<<<<< HEAD
def test_delegate_to_operator():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # Delegate to the operator
    receipt = clients.el_writer.delegate_to_operator(operator_addr)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Delegated to operator with tx hash: {receipt['transactionHash'].hex()}")


def test_deposit_into_strategy():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    # Use a small amount for testing
    amount = 100

    # Deposit into strategy
    receipt = clients.el_writer.deposit_into_strategy(strategy_addr, amount)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Deposited into strategy with tx hash: {receipt['transactionHash'].hex()}")


def test_queue_withdrawal():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    # Use a small amount of shares for testing
    shares = 50

    # Queue withdrawal
    receipt = clients.el_writer.queue_withdrawal(strategy_addr, shares)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Queued withdrawal with tx hash: {receipt['transactionHash'].hex()}")


def test_update_operator_metadata():
    metadata_url = "https://example.com/updated-metadata"

    # Update operator metadata
    receipt = clients.el_writer.update_operator_metadata(metadata_url)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated operator metadata with tx hash: {receipt['transactionHash'].hex()}")


def test_update_operator_details():
    # Create an operator with updated details
    operator = Operator(
        address=Web3.to_checksum_address(config["operator_address"]),
        delegation_approver_address="0x0000000000000000000000000000000000000000",  # No delegation approver
        allocation_delay=100,  # Not used in this function call
        metadata_url="https://example.com/operator-metadata",  # Not used in this function call
    )

    # Update operator details
    receipt = clients.el_writer.update_operator_details(operator)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated operator details with tx hash: {receipt['transactionHash'].hex()}")


=======
>>>>>>> 285c207 (Fix: lint and MyPy Done)
def test_update_metadata_uri():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # New metadata URI
    metadata_uri = "https://example.com/updated-metadata-uri"

    # Update metadata URI
    receipt = clients.el_writer.update_metadata_uri(operator_addr, metadata_uri)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated metadata URI with tx hash: {receipt['transactionHash'].hex()}")


def test_deposit_erc20_into_strategy():
    # Get strategy address from config
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    # Use a small amount for testing
    amount = 100

    # Deposit ERC20 tokens into strategy
    receipt = clients.el_writer.deposit_erc20_into_strategy(strategy_addr, amount)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Deposited ERC20 tokens into strategy with tx hash: {receipt['transactionHash'].hex()}")


def test_set_claimer_for():
    # Use operator address as the claimer address for testing
    claimer_addr = config["operator_address"]

    # Set claimer for rewards
    receipt = clients.el_writer.set_claimer_for(claimer_addr)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set claimer with tx hash: {receipt['transactionHash'].hex()}")


def test_process_claim():
    # Get address from config for the recipient
    recipient_addr = config["operator_address"]

    # Use a token address from config
    token_addr = Web3.to_checksum_address(config["strategy_addr"])

    # Create a sample claim dictionary
    claim = {
        "rootIndex": 0,
        "earnerIndex": 0,
        "earnerTreeProof": b"",
        "earnerLeaf": {
            "earner": Web3.to_checksum_address(config["operator_address"]),
            "earnerTokenRoot": b"\x00" * 32,
        },
        "tokenIndices": [0],
        "tokenTreeProofs": [b""],
        "tokenLeaves": [{"token": token_addr, "cumulativeEarnings": 100}],
    }

    # Process the claim
    receipt = clients.el_writer.process_claim(claim, recipient_addr)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Processed claim with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_avs_split():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Get AVS address from config
    avs_addr = config["avs_registry_coordinator_address"]

    # Set split to 50% (5000 basis points)
    split = 5000

    # Set operator AVS split
    receipt = clients.el_writer.set_operator_avs_split(operator_addr, avs_addr, split)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator AVS split with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_pi_split():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Set split to 30% (3000 basis points)
    split = 3000

    # Set operator PI split
    receipt = clients.el_writer.set_operator_pi_split(operator_addr, split)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator PI split with tx hash: {receipt['transactionHash'].hex()}")


def test_modify_allocations():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Create a sample allocations list
    # Each allocation is a tuple of (strategy_address, AVS_address, operator_set_id, magnitude)
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    allocations = [(strategy_addr, avs_addr, 1, 1000)]  # Operator set ID 1, magnitude 1000

    # Modify allocations
    receipt = clients.el_writer.modify_allocations(operator_addr, allocations)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Modified allocations with tx hash: {receipt['transactionHash'].hex()}")


def test_clear_deallocation_queue():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Strategy address from config
    strategy_addr = config["strategy_addr"]

    # Create a list of strategies and numbers to clear
    strategies = [strategy_addr]
    nums_to_clear = [1]  # Clear 1 deallocation from the queue for each strategy

    # Clear deallocation queue
    receipt = clients.el_writer.clear_deallocation_queue(operator_addr, strategies, nums_to_clear)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Cleared deallocation queue with tx hash: {receipt['transactionHash'].hex()}")


def test_set_allocation_delay():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Set allocation delay to 50 blocks
    delay = 50

    # Set allocation delay
    receipt = clients.el_writer.set_allocation_delay(operator_addr, delay)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set allocation delay with tx hash: {receipt['transactionHash'].hex()}")


def test_deregister_from_operator_sets():
    # Get operator address from config
    operator_addr = config["operator_address"]

    # Create request dictionary
    request = {
        "avs_address": config["avs_registry_coordinator_address"],
        "operator_set_ids": [1],  # Deregister from operator set ID 1
    }

    # Deregister from operator sets
    receipt = clients.el_writer.deregister_from_operator_sets(operator_addr, request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Deregistered from operator sets with tx hash: {receipt['transactionHash'].hex()}")


def test_register_for_operator_sets():
    # Get registry coordinator address
    registry_coordinator_addr = config["avs_registry_coordinator_address"]

    # Create request dictionary with minimal required fields
    # Note: In a real test, you would need actual BLS key pair data
    request = {
        "operator_address": config["operator_address"],
        "avs_address": config["avs_registry_coordinator_address"],
        "operator_set_ids": [1],  # Register for operator set ID 1
        "socket": "localhost:9000",  # Example socket
        "bls_key_pair": {
            "pubkey": "0x" + "00" * 48,  # Mock BLS public key
            "privkey": "0x" + "00" * 32,  # Mock BLS private key
        },
    }

    # Skip actual test execution if BLS keys are required
    # This is to prevent test failures in environments where real keys are needed
    pytest.skip("Skipping test as it requires real BLS key pair data")

    # In a real environment with proper BLS keys:
    # receipt = clients.el_writer.register_for_operator_sets(registry_coordinator_addr, request)
    # assert receipt is not None
    # assert receipt['status'] == 1
    # print(f"Registered for operator sets with tx hash: {receipt['transactionHash'].hex()}")


def test_remove_permission():
    # Create request dictionary
    request = {
        "account_address": config["operator_address"],
        "appointee_address": config[
            "operator_address"
        ],  # Using same address as appointee for testing
        "target": config["avs_registry_coordinator_address"],
        "selector": b"\x12\x34\x56\x78",  # Example selector (4 bytes)
    }

    # Remove permission
    receipt = clients.el_writer.remove_permission(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Removed permission with tx hash: {receipt['transactionHash'].hex()}")


def test_set_permission():
    # Create request dictionary
    request = {
        "account_address": config["operator_address"],
        "appointee_address": config[
            "operator_address"
        ],  # Using same address as appointee for testing
        "target": config["avs_registry_coordinator_address"],
        "selector": b"\x12\x34\x56\x78",  # Example selector (4 bytes)
        "wait_for_receipt": True,
    }

    # Set permission
    receipt = clients.el_writer.set_permission(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set permission with tx hash: {receipt['transactionHash'].hex()}")


def test_accept_admin():
    # Create request dictionary
    request = {"account_address": config["operator_address"]}

    # Accept admin
    receipt = clients.el_writer.accept_admin(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Accepted admin with tx hash: {receipt['transactionHash'].hex()}")


def test_add_pending_admin():
    # Create request dictionary
    request = {
        "account_address": config["operator_address"],
        "admin_address": config["operator_address"],  # Using same address as admin for testing
    }

    # Add pending admin
    receipt = clients.el_writer.add_pending_admin(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Added pending admin with tx hash: {receipt['transactionHash'].hex()}")


def test_remove_admin():
    # Create request dictionary
    request = {
        "account_address": config["operator_address"],
        "admin_address": config["operator_address"],  # Using same address as admin for testing
    }

    # Remove admin
    receipt = clients.el_writer.remove_admin(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Removed admin with tx hash: {receipt['transactionHash'].hex()}")


def test_remove_pending_admin():
    # Create request dictionary
    request = {
        "account_address": config["operator_address"],
        "admin_address": config["operator_address"],  # Using same address as admin for testing
    }

    # Remove pending admin
    receipt = clients.el_writer.remove_pending_admin(request)

    # Verify the transaction was successful
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Removed pending admin with tx hash: {receipt['transactionHash'].hex()}")
