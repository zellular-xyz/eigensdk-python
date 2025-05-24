import ecdsa
import pytest
from eth_account import Account
from eth_keys import keys
from eth_typing import Address
from web3 import Web3
import os
import time
from tests.builder import clients, config
from eigensdk.crypto.bls.attestation import KeyPair
from eigensdk.chainio.utils import BN254G1Point, convert_bn254_geth_to_gnark
from eigensdk.contracts import ABIs


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


def test_register_operator():
    # service_manager_addr = Web3.to_checksum_address(config["service_manager_address"])
    # avs_address = Web3.to_checksum_address(service_manager_addr)    
    # clients.el_contracts_writer.set_avs_registrar(avs_address, config["operator_address"])

    receipt = clients.avs_registry_writer.register_operator(
        operator_ecdsa_private_key=config["ecdsa_private_key"],
        bls_key_pair=KeyPair(),
        quorum_numbers=[1],
        socket="127.0.0.1:8545"
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")



# TODO: fix this function Tests
def test_update_stakes_of_entire_operator_set_for_quorums():
    return


# TODO: fix this function Tests
def test_register_operator_in_quorum_with_avs_registry_coordinator():
    return


# TODO: fix this function Tests
def test_register_operator_with_churn():
    return


# TODO: fix this function Tests
def test_deregister_operator():
    return


# TODO: fix this function Tests
def test_update_socket():
    return


# TODO: fix this function Tests
def test_set_slashable_stake_lookahead():
    return


# TODO: fix this function Tests
def test_create_slashable_stake_quorum():
    return


# TODO: fix this function Tests
def test_eject_operator():
    return


# TODO: fix this function Tests
def test_set_account_identifier():
    return


# TODO: fix this function Tests
def test_add_strategies():
    quorum_number = 0
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    strategy_params = [{"strategy": strategy_addr, "multiplier": 100}]
    
    receipt = clients.avs_registry_writer.add_strategies(quorum_number, strategy_params)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Added strategies with tx hash: {receipt['transactionHash'].hex()}")
    
    # Verify the strategy was added at index 1 (assuming index 0 is already taken)
    params = clients.avs_registry_reader.get_strategy_params_at_index(quorum_number, 1)
    assert params["strategy"] == strategy_addr
    assert params["multiplier"] == 100


# TODO: fix this function Tests
def test_remove_strategies():
    quorum_number = 0
    indices_to_remove = [0]
    
    # Verify a strategy exists at index 0 before removing
    params = clients.avs_registry_reader.get_strategy_params_at_index(quorum_number, indices_to_remove[0])
    assert params is not None  # Strategy exists at index 0
    
    # Remove the strategy
    receipt = clients.avs_registry_writer.remove_strategies(quorum_number, indices_to_remove)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Removed strategies with tx hash: {receipt['transactionHash'].hex()}")
    
    # Verify no strategies are left in the quorum
    length = clients.avs_registry_reader.get_strategy_params_length(quorum_number)
    assert length == 0


# TODO: fix this function Tests
def test_create_avs_rewards_submission():
    return


# TODO: fix this function Tests
def test_create_operator_directed_avs_rewards_submission():
    return


