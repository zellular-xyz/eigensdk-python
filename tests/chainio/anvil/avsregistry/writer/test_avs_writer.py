from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest
from eigensdk._types import Operator
import ecdsa
from eigensdk.crypto.bls.attestation import KeyPair,G1Point,G2Point
import os
from eth_keys import keys
from eth_account import Account


# TODO: Connection reverted error

# def test_register_operator():
#     operator_ecdsa_private_key = config["ecdsa_private_key"]
#     blskey = KeyPair().from_string(config["bls_private_key"])
#     quorum_numbers = [0]
#     socket = "localhost:9000"
#     receipt = clients.avs_registry_writer.register_operator(
#         operator_ecdsa_private_key=operator_ecdsa_private_key,
#         bls_key_pair=blskey,
#         quorum_numbers=quorum_numbers,
#         socket=socket
#     )
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_register_operator_in_quorum():
#     operator_ecdsa_private_key = config["ecdsa_private_key"]
#     blskey = KeyPair().from_string(config["bls_private_key"])
#     quorum_numbers = [0]  
#     socket = "localhost:9000"
#     operator_to_avs_registration_sig_salt = os.urandom(32)
#     sig_valid_for_seconds = 60 * 60  
#     current_timestamp = clients.eth_http_client.eth.get_block("latest")["timestamp"]
#     operator_to_avs_registration_sig_expiry = current_timestamp + sig_valid_for_seconds
#     receipt = clients.avs_registry_writer.register_operator_in_quorum_with_avs_registry_coordinator(
#         operator_ecdsa_private_key,
#         operator_to_avs_registration_sig_salt,
#         operator_to_avs_registration_sig_expiry,
#         blskey,
#         quorum_numbers,
#         socket,
#     )    
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator in quorum with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_update_stakes_of_entire_operator_set_for_quorums():
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     operators_per_quorum = [
#         [operator_addr],  
#     ]
#     quorum_numbers = [0]
#     receipt = clients.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
#         operators_per_quorum=operators_per_quorum,
#         quorum_numbers=quorum_numbers
#     )
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Updated operator stakes for quorums with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_register_operator_with_churn():
#     operator_ecdsa_private_key = ecdsa.SigningKey.from_string(
#         bytes.fromhex(config["operator_private_key"].replace("0x", "")), curve=ecdsa.SECP256k1
#     )
#     churn_approval_ecdsa_private_key = ecdsa.SigningKey.from_string(
#         bytes.fromhex(config["churn_approver_private_key"].replace("0x", "")),
#         curve=ecdsa.SECP256k1,
#     )
#     bls_key_pair = KeyPair.from_secret_key(config["bls_key_pair"]["privkey"])
#     quorum_numbers = [0]  
#     socket = "localhost:9000"
#     operators_to_kick = [config["operator_to_kick"]]
#     quorum_numbers_to_kick = [0]  
#     receipt = clients.avs_registry_writer.register_operator_with_churn(
#         operator_ecdsa_private_key,
#         churn_approval_ecdsa_private_key,
#         bls_key_pair,
#         quorum_numbers,
#         quorum_numbers_to_kick,
#         operators_to_kick,
#         socket,
#     )
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator with churn with tx hash: {receipt['transactionHash'].hex()}")


def test_update_stakes_of_operator_subset_for_all_quorums():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operators = [operator_addr]
    receipt = clients.avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(operators)
    assert receipt is not None
    assert receipt["status"] == 1
    print(
        f"Updated stakes for operator subset with tx hash: {receipt['transactionHash'].hex()}"
    )

# TODO: Connection reverted error

# def test_deregister_operator():
#     quorum_numbers = [0]  
#     receipt = clients.avs_registry_writer.deregister_operator(quorum_numbers)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Deregistered operator with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_update_socket():
#     new_socket = "localhost:9001"
#     receipt = clients.avs_registry_writer.update_socket(new_socket)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Updated operator socket with tx hash: {receipt['transactionHash'].hex()}")


def test_set_rewards_initiator():
    rewards_initiator_addr = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_rewards_initiator(rewards_initiator_addr)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set rewards initiator with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_set_slashable_stake_lookahead():
#     quorum_number = 0
#     look_ahead_period = 100  
#     receipt = clients.avs_registry_writer.set_slashable_stake_lookahead(quorum_number, look_ahead_period)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Set slashable stake lookahead with tx hash: {receipt['transactionHash'].hex()}")


def test_set_minimum_stake_for_quorum():
    quorum_number = 0
    minimum_stake = 1000000  
    receipt = clients.avs_registry_writer.set_minimum_stake_for_quorum(quorum_number, minimum_stake)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set minimum stake for quorum with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_create_total_delegated_stake_quorum():
#     operator_set_params = {
#         "maxOperatorCount": 10,
#         "kickBIPsOfOperatorStake": 10000,  
#         "kickBIPsOfTotalStake": 2000,  
#     }
#     minimum_stake_required = 1000000  
#     strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#     strategy_params = [{"strategy": strategy_addr, "multiplier": 10000}]  
#     receipt = clients.avs_registry_writer.create_total_delegated_stake_quorum(
#         operator_set_params, minimum_stake_required, strategy_params
#     )
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(
#         f"Created total delegated stake quorum with tx hash: {receipt['transactionHash'].hex()}"
#     )

# TODO: Connection reverted error

# def test_create_slashable_stake_quorum():
#     operator_set_params = {
#         "maxOperatorCount": 10,
#         "kickBIPsOfOperatorStake": 10000,  
#         "kickBIPsOfTotalStake": 2000,  
#     }
#     minimum_stake_required = 1000000  
#     strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#     strategy_params = [{"strategy": strategy_addr, "multiplier": 10000}]  
#     look_ahead_period = 100  
#     receipt = clients.avs_registry_writer.create_slashable_stake_quorum(
#         operator_set_params, minimum_stake_required, strategy_params, look_ahead_period
#     )    
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Created slashable stake quorum with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_eject_operator():
#     operator_to_eject = config["operator_address"]
#     operator_address = Web3.to_checksum_address(operator_to_eject)
#     quorum_numbers = [0]  
#     receipt = clients.avs_registry_writer.eject_operator(operator_address, quorum_numbers)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Ejected operator with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_set_params():
    quorum_number = 0
    operator_set_params = {
        "maxOperatorCount": 10,
        "kickBIPsOfOperatorStake": 10000,  
        "kickBIPsOfTotalStake": 2000,  
    }
    receipt = clients.avs_registry_writer.set_operator_set_params(quorum_number, operator_set_params)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator set params with tx hash: {receipt['transactionHash'].hex()}")


def test_set_churn_approver():
    churn_approver_address = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_churn_approver(churn_approver_address)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set churn approver with tx hash: {receipt['transactionHash'].hex()}")

def test_set_ejector():
    ejector_address = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_ejector(ejector_address)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set ejector with tx hash: {receipt['transactionHash'].hex()}")


def test_modify_strategy_params():
    quorum_number = 0
    strategy_indices = [0]  
    multipliers = [8000]  
    receipt = clients.avs_registry_writer.modify_strategy_params(
        quorum_number, strategy_indices, multipliers
    )    
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Modified strategy parameters with tx hash: {receipt['transactionHash'].hex()}")


# TODO: Connection reverted error

# def test_set_account_identifier():
#     account_identifier_address = Web3.to_checksum_address(config["operator_address"])    
#     receipt = clients.avs_registry_writer.set_account_identifier(account_identifier_address)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Set account identifier with tx hash: {receipt['transactionHash'].hex()}")


def test_set_ejection_cooldown():
    ejection_cooldown = 100  
    receipt = clients.avs_registry_writer.set_ejection_cooldown(ejection_cooldown)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set ejection cooldown with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_add_strategies():
#     quorum_number = 0
#     strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#     strategy_params = [{"strategy": strategy_addr, "multiplier": 5000}]  
#     receipt = clients.avs_registry_writer.add_strategies(quorum_number, strategy_params)    
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Added strategies to quorum with tx hash: {receipt['transactionHash'].hex()}")


def test_update_avs_metadata_uri():
    metadata_uri = "https://example.com/avs-metadata-updated"
    receipt = clients.avs_registry_writer.update_avs_metadata_uri(metadata_uri)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated AVS metadata URI with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_remove_strategies():
#     quorum_number = 0
#     indices_to_remove = [1]  
#     receipt = clients.avs_registry_writer.remove_strategies(quorum_number, indices_to_remove)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Removed strategies from quorum with tx hash: {receipt['transactionHash'].hex()}")


# TODO: Connection reverted error

# def test_create_avs_rewards_submission():
#     rewards_submission = [
#         {
#             "blockNumber": clients.eth_http_client.eth.block_number - 100,
#             "tokenAddr": Web3.to_checksum_address(config["strategy_addr"]),
#             "amount": 1000000,  
#             "earnerAddr": Web3.to_checksum_address(config["operator_address"]),
#         }
#     ]
#     receipt = clients.avs_registry_writer.create_avs_rewards_submission(rewards_submission)
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Created AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}")

# TODO: Connection reverted error

# def test_create_operator_directed_avs_rewards_submission():
#     operator_directed_rewards_submissions = [
#         {
#             "operator": Web3.to_checksum_address(config["operator_address"]),
#             "tokenAddr": Web3.to_checksum_address(config["strategy_addr"]),
#             "amount": 1000000,  
#             "earnerAddr": Web3.to_checksum_address(config["operator_address"]),
#         }
#     ]
#     receipt = clients.avs_registry_writer.create_operator_directed_avs_rewards_submission(
#         operator_directed_rewards_submissions
#     )
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(
#         f"Created operator-directed AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}"
#     )