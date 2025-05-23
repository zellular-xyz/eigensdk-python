from web3 import Web3
from unittest.mock import patch, MagicMock

from eigensdk._types import Operator
from tests.builder import clients, clients_2, config
from eigensdk.crypto.bls.attestation import KeyPair

def advance_chain_by_n_blocks(web3_client, n: int):
    for _ in range(n):
        web3_client.provider.make_request("evm_mine", [])

def test_register_as_operator():
    operator = Operator(
        address=Web3.to_checksum_address(config["operator_address"]),
        earnings_receiver_address=Web3.to_checksum_address(config["operator_address"]),
        delegation_approver_address=Web3.to_checksum_address(config["operator_address"]),
        allocation_delay=50,
        metadata_url="https://example.com/operator-metadata",
        staker_opt_out_window_blocks=100,
    )
    receipt = clients.el_writer.register_as_operator(operator)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")

def test_register_for_operator_sets():
    request = {
            "operator_address": config["operator_address"],
            "avs_address": config["service_manager_address"],
            "operator_set_ids": [0],
            "socket": "operator-socket",
            "bls_key_pair": KeyPair(),
        }
    receipt = clients.el_writer.register_for_operator_sets(
        config["avs_registry_coordinator_address"],
        request
    )
    assert receipt["status"] == 1
    print(f"Registered for operator sets with tx hash: {receipt['transactionHash'].hex()}")

def test_deregister_from_operator_sets():

    # Now deregister from the same operator sets
    operator_address = config["operator_address"]
    request = {
        "avs_address": config["service_manager_address"],
        "operator_set_ids": [0],
    }
    
    receipt = clients.el_writer.deregister_from_operator_sets(
        operator_address,
        request
    )
    
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Deregistered from operator sets with tx hash: {receipt['transactionHash'].hex()}")


def test_update_metadata_uri():
    operator_addr = config["operator_address"]
    metadata_uri = "https://example.com/updated-metadata-uri"
    receipt = clients.el_writer.update_metadata_uri(operator_addr, metadata_uri)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated metadata URI with tx hash: {receipt['transactionHash'].hex()}")


def test_deposit_erc20_into_strategy():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    amount = 100
    receipt = clients.el_writer.deposit_erc20_into_strategy(strategy_addr, amount)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Deposited ERC20 tokens into strategy with tx hash: {receipt['transactionHash'].hex()}")


def test_set_claimer_for():
    claimer_addr = config["operator_address"]
    receipt = clients.el_writer.set_claimer_for(claimer_addr)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set claimer with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_avs_split():
    operator_addr = config["operator_address"]
    avs_addr = config["avs_address"]
    split = 5000
    receipt = clients.el_writer.set_operator_avs_split(operator_addr, avs_addr, split)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator AVS split with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_pi_split():
    operator_addr = config["operator_address"]
    split = 3000
    receipt = clients.el_writer.set_operator_pi_split(operator_addr, split)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator PI split with tx hash: {receipt['transactionHash'].hex()}")


def test_clear_deallocation_queue():
    operator_addr = config["operator_address"]
    strategy_addr = config["strategy_addr"]
    strategies = [strategy_addr]
    nums_to_clear = [1]
    receipt = clients.el_writer.clear_deallocation_queue(operator_addr, strategies, nums_to_clear)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Cleared deallocation queue with tx hash: {receipt['transactionHash'].hex()}")


def test_set_allocation_delay():
    operator_addr = config["operator_address"]
    delay = 50
    receipt = clients.el_writer.set_allocation_delay(operator_addr, delay)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set allocation delay with tx hash: {receipt['transactionHash'].hex()}")


def test_add_pending_admin():
    request = {
        "account_address": config["operator_address"],
        "admin_address": config["operator_address"],
    }
    receipt = clients.el_writer.add_pending_admin(request)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Added pending admin with tx hash: {receipt['transactionHash'].hex()}")


def test_remove_pending_admin():
    request = {
        "account_address": config["operator_address"],
        "admin_address": config["operator_address"],
    }
    receipt = clients.el_writer.remove_pending_admin(request)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Removed pending admin with tx hash: {receipt['transactionHash'].hex()}")


def test_accept_admin():
    test_add_pending_admin()
    request = {"account_address": config["operator_address"]}
    receipt = clients.el_writer.accept_admin(request)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Accepted admin with tx hash: {receipt['transactionHash'].hex()}")


def test_set_permission():
    receipt = clients.el_writer.set_permission(
        {
            "account_address": config["operator_address"],
            "appointee_address": config["operator_address"],
            "target": config["avs_address"],
            "selector": "0x00000000",
        }
    )
    assert receipt["status"] == 1


def test_set_permission():
    request = {
        "account_address": config["operator_address"],
        "appointee_address": config["operator_address"],
        "target": config["avs_address"],
        "selector": "0x12345678",
    }
    receipt = clients.el_writer.set_permission(request)
    assert receipt["status"] == 1


def test_remove_permission():
    request = {
        "account_address": config["operator_address"],
        "appointee_address": config["operator_address"],
        "target": config["avs_address"],
        "selector": "0x12345678",
    }
    receipt = clients.el_writer.remove_permission(request)
    assert receipt["status"] == 1


def test_remove_admin_flow():
    account_address = Web3.to_checksum_address(config["operator_address"])
    admin2_address = Web3.to_checksum_address(config["admin2_address"])

    receipt = clients.el_writer.add_pending_admin(
        {
            "account_address": account_address,
            "admin_address": admin2_address,
            "wait_for_receipt": True,
        }
    )
    assert receipt["status"] == 1, f"Transaction failed: {receipt}"

    receipt = clients_2.el_writer.accept_admin(
        {
            "account_address": account_address,
        }
    )
    assert receipt["status"] == 1, f"Transaction failed: {receipt}"

    receipt = clients.el_writer.remove_admin(
        {
            "account_address": account_address,
            "admin_address": admin2_address,
        }
    )
    assert receipt["status"] == 1, f"Transaction failed: {receipt}"



def test_modify_allocations():
    # Get the operator address from config
    operator_address = config["operator_address"]
    
    # Set up parameters for modify_allocations
    avs_service_manager = config["service_manager_address"]
    operator_set_id = 0
    strategies = [config["strategy_addr"]]
    new_magnitudes = [1000]
    
    receipt = clients.el_writer.modify_allocations(
        operator_address,
        avs_service_manager,
        operator_set_id,
        strategies,
        new_magnitudes
    )
    
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Modified allocations with tx hash: {receipt['transactionHash'].hex()}")
