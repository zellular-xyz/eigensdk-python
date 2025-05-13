from tests.builder import clients, config
from web3 import Web3
from eigensdk._types import Operator
from eigensdk.chainio.utils import nums_to_bytes


def test_register_as_operator():
    operator = Operator(
        address=Web3.to_checksum_address(config["operator_address"]),
        earnings_receiver_address=Web3.to_checksum_address(config["operator_address"]),
        delegation_approver_address="0x0000000000000000000000000000000000000000",
        allocation_delay=100,
        metadata_url="https://example.com/operator-metadata",
        staker_opt_out_window_blocks=100,
    )
    receipt = clients.el_writer.register_as_operator(operator)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")


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


# TODO: fix this test, unknown error
# def test_process_claim():
#     recipient_addr = Web3.to_checksum_address(config["operator_address"])
#     token_addr = Web3.to_checksum_address(config["strategy_addr"])
#     claim = {
#         "rootIndex": 0,
#         "earnerIndex": 0,
#         "earnerTreeProof": nums_to_bytes([0] * 32),
#         "earnerLeaf": {
#             "earner": recipient_addr,
#             "earnerTokenRoot": nums_to_bytes([0] * 32),
#         },
#         "tokenIndices": [0],
#         "tokenTreeProofs": [nums_to_bytes([0] * 32)],
#         "tokenLeaves": [
#             {
#                 "token": token_addr,
#                 "cumulativeEarnings": 100,
#             }
#         ],
#     }
#     receipt = clients.el_writer.process_claim(claim, recipient_addr)
#     print("\n\n\n\n",receipt,"\n\n\n\n")
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Processed claim with tx hash: {receipt['transactionHash'].hex()}")


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


# TODO: fix this test, set correct avs address

# def test_modify_allocations():
#     operator_addr = config["operator_address"]
#     strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#     avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
#     allocations = [{
#         "operatorSet": {
#             "id": 1,
#             "avs": avs_addr
#         },
#         "strategies": [strategy_addr],
#         "newMagnitudes": [1000]
#     }]
#     receipt = clients.el_writer.modify_allocations(operator_addr, allocations)
#     print("\n\n\n\n",receipt,"\n\n\n\n")
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Modified allocations with tx hash: {receipt['transactionHash'].hex()}")


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


# TODO: fix this test, unknown error

# def test_register_for_operator_sets():
#     registry_coordinator_addr = config["avs_registry_coordinator_address"]
#     request = {
#         "operator_address": config["operator_address"],
#         "avs_address": config["avs_registry_coordinator_address"],
#         "operator_set_ids": [1],
#         "socket": "localhost:9000",
#         "bls_key_pair": {
#             "pubkey": "0x" + "00" * 48,  # 48 bytes for BLS public key
#             "privkey": "0x" + "00" * 32,  # 32 bytes for BLS private key
#         },
#     }

#     receipt = clients.el_writer.register_for_operator_sets(registry_coordinator_addr, request)
#     print(f"\nTransaction hash: {receipt['transactionHash'].hex()}")
#     print(f"Transaction status: {receipt['status']}")
#     if receipt['status'] == 0:
#         try:
#             tx = clients.el_writer.eth_http_client.eth.get_transaction(receipt['transactionHash'])
#             print(f"Transaction input: {tx['input']}")
#             print(f"Gas used: {receipt['gasUsed']}")
#             print(f"Block number: {receipt['blockNumber']}")
#         except Exception as e:
#             print(f"Could not get transaction details: {str(e)}")

#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered for operator sets with tx hash: {receipt['transactionHash'].hex()}")


# TODO: fix this test, set correct avs address

# def test_deregister_from_operator_sets():
#     operator_addr = config["operator_address"]
#     request = {
#         "avs_address": config["avs_registry_coordinator_address"],
#         "operator_set_ids": [1],
#     }
#     receipt = clients.el_writer.deregister_from_operator_sets(operator_addr, request)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Deregistered from operator sets with tx hash: {receipt['transactionHash'].hex()}")


# TODO: fix this test, unknown error, Maybe because of the target is not a contract or correct contract address.

# def test_set_permission():
#     request = {
#         "account_address": config["operator_address"],
#         "appointee_address": config[
#             "operator_address"
#         ],
#         "target": config["avs_address"],
#         "selector": nums_to_bytes([12, 34, 56, 78]),
#         "wait_for_receipt": True,
#     }
#     receipt = clients.el_writer.set_permission(request)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Set permission with tx hash: {receipt['transactionHash'].hex()}")


# TODO: fix this test, unknown error, Maybe because of the target is not a contract or correct contract address.

# def test_remove_permission():
#     request = {
#         "account_address": config["operator_address"],
#         "appointee_address": config[
#             "operator_address"
#         ],
#         "target": config["avs_registry_coordinator_address"],
#         "selector": b"\x12\x34\x56\x78",
#     }
#     receipt = clients.el_writer.remove_permission(request)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Removed permission with tx hash: {receipt['transactionHash'].hex()}")


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


# TODO: fix this test, unknown error reverted with no reason

# def test_remove_admin():
#     test_accept_admin()
#     request = {
#         "account_address": config["operator_address"],
#         "admin_address": config["operator_address"],
#     }
#     receipt = clients.el_writer.remove_admin(request)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Removed admin with tx hash: {receipt['transactionHash'].hex()}")
