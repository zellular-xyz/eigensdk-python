from web3 import Web3
from eigensdk.crypto.bls import KeyPair
from eth_utils import to_checksum_address
from tests.builder import clients_array, config
from eigensdk.chainio.clients.elcontracts.writer import Operator
import time


def test_register_as_operator_for_operator_sets():
    for i in range(1, 4):
        address = to_checksum_address(config["operator_address_{}".format(i)])
        operator = Operator(
            address=address,
            earnings_receiver_address=address,
            delegation_approver_address=Web3.to_checksum_address(
                "0x0000000000000000000000000000000000000000"
            ),
            allocation_delay=50,
            metadata_url="https://example.com/operator-metadata",
            staker_opt_out_window_blocks=100,
        )
        receipt = clients_array[i - 1].el_writer.register_as_operator(operator)
        assert receipt is not None
        assert receipt["status"] == 1
        print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")
        request = {
            "operator_address": address,
            "avs_address": config["service_manager_address"],
            "operator_set_ids": [0],
            "socket": "operator-socket",
            "bls_key_pair": KeyPair(),
        }
        receipt = clients_array[i - 1].el_writer.register_for_operator_sets(
            config["avs_registry_coordinator_address"], request
        )
        assert receipt["status"] == 1
        print(f"Registered for operator sets with tx hash: {receipt['transactionHash'].hex()}")
        time.sleep(1)
