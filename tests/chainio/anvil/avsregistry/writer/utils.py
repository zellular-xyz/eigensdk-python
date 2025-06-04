from eth_utils import to_checksum_address

from eigensdk.crypto.bls import KeyPair
from eigensdk.types_ import Operator
from tests.builder import clients, config
from tests.test_utils import generate_random_address


def register_as_operator(operator_address=config["operator_address"]):
    address = to_checksum_address(operator_address)
    operator = Operator(
        address=address,
        earnings_receiver_address=address,
        delegation_approver_address=address,
        allocation_delay=50,
        metadata_url="https://example.com/operator-metadata",
        staker_opt_out_window_blocks=100,
    )
    receipt = clients.el_writer.register_as_operator(operator)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")


def register_random_operator():
    register_as_operator(generate_random_address())


def register_for_operator_sets():
    request = {
        "operator_address": config["operator_address"],
        "avs_address": config["service_manager_address"],
        "operator_set_ids": [0],
        "socket": "operator-socket",
        "bls_key_pair": KeyPair(),
    }
    receipt = clients.el_writer.register_for_operator_sets(
        config["avs_registry_coordinator_address"], request
    )
    assert receipt["status"] == 1
    print(f"Registered for operator sets with tx hash: {receipt['transactionHash'].hex()}")
