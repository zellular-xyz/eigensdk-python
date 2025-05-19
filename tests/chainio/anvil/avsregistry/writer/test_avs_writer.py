import ecdsa
import pytest
from eth_account import Account
from eth_keys import keys
from eth_typing import Address
from web3 import Web3
import os
import time

from tests.builder import clients, config
from eigensdk.crypto.bls.key_pair import KeyPair


# def test_register_operator():
#     operator_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
#     bls_key_pair = KeyPair.generate()
    
#     quorum_numbers = [0]
#     socket = "127.0.0.1:1234"
    
#     receipt = clients.avs_registry_writer.register_operator(
#         operator_ecdsa_private_key=operator_private_key,
#         bls_key_pair=bls_key_pair,
#         quorum_numbers=quorum_numbers,
#         socket=socket
#     )
    
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")




def test_update_stakes_of_operator_subset_for_all_quorums():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operators = [operator_addr]
    receipt = clients.avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(
        operators
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated stakes for operator subset with tx hash: {receipt['transactionHash'].hex()}")


def test_set_rewards_initiator():
    rewards_initiator_addr = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_rewards_initiator(rewards_initiator_addr)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set rewards initiator with tx hash: {receipt['transactionHash'].hex()}")


def test_set_minimum_stake_for_quorum():
    quorum_number = 0
    minimum_stake = 1000000
    receipt = clients.avs_registry_writer.set_minimum_stake_for_quorum(quorum_number, minimum_stake)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set minimum stake for quorum with tx hash: {receipt['transactionHash'].hex()}")


def test_create_total_delegated_stake_quorum():
    operator_set_params = (
        10,  # maxOperatorCount (uint32)
        10000,  # kickBIPsOfOperatorStake (uint16)
        2000,  # kickBIPsOfTotalStake (uint16)
    )
    minimum_stake_required = 1000000
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    strategy_params = [(strategy_addr, 10000)]
    receipt = clients.avs_registry_writer.create_total_delegated_stake_quorum(
        operator_set_params, minimum_stake_required, strategy_params
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Created total delegated stake quorum with tx hash: {receipt['transactionHash'].hex()}")


def test_set_operator_set_params():
    quorum_number = 0
    operator_set_params = {
        "maxOperatorCount": 10,
        "kickBIPsOfOperatorStake": 10000,
        "kickBIPsOfTotalStake": 2000,
    }
    receipt = clients.avs_registry_writer.set_operator_set_params(
        quorum_number, operator_set_params
    )
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


def test_set_ejection_cooldown():
    ejection_cooldown = 100
    receipt = clients.avs_registry_writer.set_ejection_cooldown(ejection_cooldown)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set ejection cooldown with tx hash: {receipt['transactionHash'].hex()}")


def test_update_avs_metadata_uri():
    metadata_uri = "https://example.com/avs-metadata-updated"
    receipt = clients.avs_registry_writer.update_avs_metadata_uri(metadata_uri)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated AVS metadata URI with tx hash: {receipt['transactionHash'].hex()}")


# def test_update_stakes_of_entire_operator_set_for_quorums():
#     # Test parameters
#     operator_addr = Web3.to_checksum_address(config["operator_address"])
#     operators_per_quorum = [[operator_addr]]  # One operator in quorum 0
#     quorum_numbers = [0]  # Update quorum 0
    
#     # Update stakes
#     receipt = clients.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
#         operators_per_quorum=operators_per_quorum,
#         quorum_numbers=quorum_numbers
#     )
    
#     # Verify receipt
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Updated stakes of entire operator set with tx hash: {receipt['transactionHash'].hex()}")


# def test_register_operator_in_quorum_with_avs_registry_coordinator():
#     # Create test operator key pair
#     operator_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
#     bls_key_pair = KeyPair.generate()
    
#     # Test parameters
#     quorum_numbers = [0]  # Register for quorum 0
#     socket = "127.0.0.1:1234"  # Test socket address
#     signature_salt = os.urandom(32)
#     signature_expiry = int(time.time()) + 3600  # 1 hour from now
    
#     # Register operator
#     receipt = clients.avs_registry_writer.register_operator_in_quorum_with_avs_registry_coordinator(
#         operator_ecdsa_private_key=operator_private_key.to_string().hex(),
#         operator_to_avs_registration_sig_salt=signature_salt,
#         operator_to_avs_registration_sig_expiry=signature_expiry,
#         bls_key_pair=bls_key_pair,
#         quorum_numbers=quorum_numbers,
#         socket=socket
#     )
    
#     # Verify receipt
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator in quorum with tx hash: {receipt['transactionHash'].hex()}")


# def test_register_operator_with_churn():
#     # Create test key pairs
#     operator_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
#     churn_approval_private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
#     bls_key_pair = KeyPair.generate()
    
#     # Test parameters
#     quorum_numbers = [0]  # Register for quorum 0
#     quorum_numbers_to_kick = [0]  # Kick from quorum 0
#     operators_to_kick = [Web3.to_checksum_address(config["operator_address"])]  # Kick existing operator
#     socket = "127.0.0.1:1234"  # Test socket address
    
#     # Register operator with churn
#     receipt = clients.avs_registry_writer.register_operator_with_churn(
#         operator_ecdsa_private_key=operator_private_key,
#         churn_approval_ecdsa_private_key=churn_approval_private_key,
#         bls_key_pair=bls_key_pair,
#         quorum_numbers=quorum_numbers,
#         quorum_numbers_to_kick=quorum_numbers_to_kick,
#         operators_to_kick=operators_to_kick,
#         socket=socket
#     )
    
#     # Verify receipt
#     assert receipt is not None
#     assert receipt["status"] == 1
#     print(f"Registered operator with churn with tx hash: {receipt['transactionHash'].hex()}")


# def test_deregister_operator():
#     receipt = clients.avs_registry_writer.deregister_operator([0])
#     assert receipt["status"] == 1

# def test_update_socket():
#     receipt = clients.avs_registry_writer.update_socket("127.0.0.1:1234")
#     assert receipt["status"] == 1

# def test_set_slashable_stake_lookahead():
#     receipt = clients.avs_registry_writer.set_slashable_stake_lookahead(0, 100)
#     assert receipt["status"] == 1

# def test_create_slashable_stake_quorum():
#     receipt = clients.avs_registry_writer.create_slashable_stake_quorum(
#         {"maxOperatorCount": 10, "kickBIPsOfOperatorStake": 10000, "kickBIPsOfTotalStake": 2000},
#         1000000,
#         [{"strategy": config["strategy_addr"], "multiplier": 10000}],
#         100
#     )
#     assert receipt["status"] == 1

# def test_eject_operator():
#     receipt = clients.avs_registry_writer.eject_operator(config["operator_address"], [0])
#     assert receipt["status"] == 1

# def test_set_account_identifier():
#     receipt = clients.avs_registry_writer.set_account_identifier(config["operator_address"])
#     assert receipt["status"] == 1

# def test_add_strategies():
#     receipt = clients.avs_registry_writer.add_strategies(0, [{"strategy": config["strategy_addr"], "multiplier": 10000}])
#     assert receipt["status"] == 1

# def test_remove_strategies():
#     receipt = clients.avs_registry_writer.remove_strategies(0, [0])
#     assert receipt["status"] == 1

# def test_create_avs_rewards_submission():
#     receipt = clients.avs_registry_writer.create_avs_rewards_submission([{"operator": config["operator_address"], "amount": 1000000}])
#     assert receipt["status"] == 1

# def test_create_operator_directed_avs_rewards_submission():
#     receipt = clients.avs_registry_writer.create_operator_directed_avs_rewards_submission([{"operator": config["operator_address"], "amount": 1000000}])
#     assert receipt["status"] == 1
