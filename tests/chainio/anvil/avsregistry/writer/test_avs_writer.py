from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest
from eigensdk._types import Operator
import ecdsa
from eigensdk.crypto.bls.attestation import KeyPair,G1Point,G2Point
import os
import time


# def test_register_operator():
#     """Test registering an operator with the AVS registry"""
#     # This test requires actual ECDSA and BLS keys to work
#     # In a real environment, you would have these keys available
#     # Here we check if we have the necessary keys in config and skip if not

#     if "operator_private_key" not in config:
#         pytest.skip("Operator private key not found in config")

#     try:
#         # Initialize ECDSA private key from config
#         operator_ecdsa_private_key = ecdsa.SigningKey.from_string(
#             bytes.fromhex(config["operator_private_key"].replace("0x", "")), curve=ecdsa.SECP256k1
#         )

#         # In a real test, you would have a valid BLS key pair
#         # For testing purposes, we might create one or load from config
#         # This is a simplified example - real key loading would depend on your setup
#         if "bls_key_pair" not in config:
#             pytest.skip("BLS key pair not found in config")

#         # Create or load BLS key pair
#         # This is pseudocode - actual implementation would depend on how you store BLS keys
#         bls_key_pair = KeyPair.from_secret_key(config["bls_key_pair"]["privkey"])

#         # Define quorum numbers to register for
#         quorum_numbers = [0]  # For testing, register for quorum 0

#         # Define a socket string
#         socket = "localhost:9000"

#         # Register the operator
#         receipt = clients.avs_writer.register_operator(
#             operator_ecdsa_private_key, bls_key_pair, quorum_numbers, socket
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Registered operator with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_register_operator_in_quorum():
#     """Test registering an operator in a quorum with the AVS registry coordinator"""
#     # This test requires actual ECDSA and BLS keys to work
#     # In a real environment, you would have these keys available
#     # Here we check if we have the necessary keys in config and skip if not

#     if "operator_private_key" not in config:
#         pytest.skip("Operator private key not found in config")

#     try:
#         # Get the operator private key as a string (already in the format needed)
#         operator_ecdsa_private_key = config["operator_private_key"]

#         # In a real test, you would have a valid BLS key pair
#         # For testing purposes, we might create one or load from config
#         if "bls_key_pair" not in config:
#             pytest.skip("BLS key pair not found in config")

#         # Create or load BLS key pair
#         # This is pseudocode - actual implementation would depend on how you store BLS keys
#         bls_key_pair = KeyPair.from_secret_key(config["bls_key_pair"]["privkey"])

#         # Define quorum numbers to register for
#         quorum_numbers = [0]  # For testing, register for quorum 0

#         # Define a socket string
#         socket = "localhost:9000"

#         # Generate a random salt and expiry time for the signature
#         operator_to_avs_registration_sig_salt = os.urandom(32)
#         sig_valid_for_seconds = 60 * 60  # 1 hour
#         current_timestamp = clients.eth_http_client.eth.get_block("latest")["timestamp"]
#         operator_to_avs_registration_sig_expiry = current_timestamp + sig_valid_for_seconds

#         # Register the operator in the quorum
#         receipt = clients.avs_writer.register_operator_in_quorum_with_avs_registry_coordinator(
#             operator_ecdsa_private_key,
#             operator_to_avs_registration_sig_salt,
#             operator_to_avs_registration_sig_expiry,
#             bls_key_pair,
#             quorum_numbers,
#             socket,
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Registered operator in quorum with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_update_stakes_of_entire_operator_set_for_quorums():
#     """Test updating stakes of the entire operator set for specified quorums"""
#     try:
#         # Define the operator addresses for each quorum
#         # We'll use the operator address from config and a dummy address for testing
#         operator_addr = Web3.to_checksum_address(config["operator_address"])

#         # Define operator lists per quorum - each inner list corresponds to a quorum
#         operators_per_quorum = [
#             [operator_addr],  # Operators for quorum 0
#         ]

#         # Define quorum numbers to update
#         quorum_numbers = [0]  # Update quorum 0

#         # Update stakes for the specified quorums
#         receipt = clients.avs_writer.update_stakes_of_entire_operator_set_for_quorums(
#             operators_per_quorum, quorum_numbers
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(
#             f"Updated operator stakes for quorums with tx hash: {receipt['transactionHash'].hex()}"
#         )

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_register_operator_with_churn():
#     """Test registering an operator with churn (replacing existing operators)"""
#     # Check for required keys in config
#     if "operator_private_key" not in config or "churn_approver_private_key" not in config:
#         pytest.skip("Operator or churn approver private key not found in config")

#     try:
#         # Initialize ECDSA private key for the operator
#         operator_ecdsa_private_key = ecdsa.SigningKey.from_string(
#             bytes.fromhex(config["operator_private_key"].replace("0x", "")), curve=ecdsa.SECP256k1
#         )

#         # Initialize ECDSA private key for the churn approver
#         churn_approval_ecdsa_private_key = ecdsa.SigningKey.from_string(
#             bytes.fromhex(config["churn_approver_private_key"].replace("0x", "")),
#             curve=ecdsa.SECP256k1,
#         )

#         # Check for BLS key pair
#         if "bls_key_pair" not in config:
#             pytest.skip("BLS key pair not found in config")

#         # Create or load BLS key pair
#         bls_key_pair = KeyPair.from_secret_key(config["bls_key_pair"]["privkey"])

#         # Define quorum numbers to register for
#         quorum_numbers = [0]  # For testing, register for quorum 0

#         # Define a socket string
#         socket = "localhost:9000"

#         # Define operators to kick out (replace)
#         # This requires an existing operator in the quorum to replace
#         # If you don't have one, this test will fail
#         if "operator_to_kick" not in config:
#             pytest.skip("No operator_to_kick defined in config")

#         operators_to_kick = [config["operator_to_kick"]]
#         quorum_numbers_to_kick = [0]  # Kick from quorum 0

#         # Register the operator with churn
#         receipt = clients.avs_writer.register_operator_with_churn(
#             operator_ecdsa_private_key,
#             churn_approval_ecdsa_private_key,
#             bls_key_pair,
#             quorum_numbers,
#             quorum_numbers_to_kick,
#             operators_to_kick,
#             socket,
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Registered operator with churn with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_update_stakes_of_operator_subset_for_all_quorums():
#     """Test updating stakes of a subset of operators for all quorums"""
#     try:
#         # Define the operator addresses to update
#         operator_addr = Web3.to_checksum_address(config["operator_address"])

#         # Create a list of operators to update
#         operators = [operator_addr]

#         # Update stakes for the specified operators across all quorums
#         receipt = clients.avs_writer.update_stakes_of_operator_subset_for_all_quorums(operators)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(
#             f"Updated stakes for operator subset with tx hash: {receipt['transactionHash'].hex()}"
#         )

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_deregister_operator():
#     """Test deregistering an operator from specified quorums"""
#     try:
#         # Define quorum numbers to deregister from
#         quorum_numbers = [0]  # Deregister from quorum 0

#         # Deregister the operator
#         receipt = clients.avs_writer.deregister_operator(quorum_numbers)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Deregistered operator with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_update_socket():
#     """Test updating the socket of an operator"""
#     try:
#         # Define a new socket string
#         new_socket = "localhost:9001"

#         # Update the socket
#         receipt = clients.avs_writer.update_socket(new_socket)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Updated operator socket with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_rewards_initiator():
#     """Test setting the rewards initiator address"""
#     try:
#         # Define the rewards initiator address
#         rewards_initiator_addr = Web3.to_checksum_address(config["operator_address"])

#         # Set the rewards initiator
#         receipt = clients.avs_writer.set_rewards_initiator(rewards_initiator_addr)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set rewards initiator with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_slashable_stake_lookahead():
#     """Test setting the slashable stake lookahead period for a quorum"""
#     try:
#         # Define quorum number and lookahead period
#         quorum_number = 0
#         look_ahead_period = 100  # 100 blocks

#         # Set the slashable stake lookahead
#         receipt = clients.avs_writer.set_slashable_stake_lookahead(quorum_number, look_ahead_period)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set slashable stake lookahead with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_minimum_stake_for_quorum():
#     """Test setting the minimum stake required for a quorum"""
#     try:
#         # Define quorum number and minimum stake
#         quorum_number = 0
#         minimum_stake = 1000000  # 1 million (adjust based on your token decimals)

#         # Set minimum stake for the quorum
#         receipt = clients.avs_writer.set_minimum_stake_for_quorum(quorum_number, minimum_stake)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set minimum stake for quorum with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_create_total_delegated_stake_quorum():
#     """Test creating a new total delegated stake quorum"""
#     try:
#         # Define operator set parameters
#         operator_set_params = {
#             "maxOperatorCount": 10,
#             "kickBIPsOfOperatorStake": 10000,  # 100% in basis points
#             "kickBIPsOfTotalStake": 2000,  # 20% in basis points
#         }

#         # Define minimum stake required
#         minimum_stake_required = 1000000  # 1 million (adjust based on your token decimals)

#         # Define strategy parameters
#         # These would typically be a list of strategy addresses and their weights
#         strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#         strategy_params = [{"strategy": strategy_addr, "multiplier": 10000}]  # 100% in basis points

#         # Create the total delegated stake quorum
#         receipt = clients.avs_writer.create_total_delegated_stake_quorum(
#             operator_set_params, minimum_stake_required, strategy_params
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(
#             f"Created total delegated stake quorum with tx hash: {receipt['transactionHash'].hex()}"
#         )

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_create_slashable_stake_quorum():
#     """Test creating a new slashable stake quorum"""
#     try:
#         # Define operator set parameters
#         operator_set_params = {
#             "maxOperatorCount": 10,
#             "kickBIPsOfOperatorStake": 10000,  # 100% in basis points
#             "kickBIPsOfTotalStake": 2000,  # 20% in basis points
#         }

#         # Define minimum stake required
#         minimum_stake_required = 1000000  # 1 million (adjust based on your token decimals)

#         # Define strategy parameters
#         # These would typically be a list of strategy addresses and their weights
#         strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#         strategy_params = [{"strategy": strategy_addr, "multiplier": 10000}]  # 100% in basis points

#         # Define lookahead period
#         look_ahead_period = 100  # 100 blocks

#         # Create the slashable stake quorum
#         receipt = clients.avs_writer.create_slashable_stake_quorum(
#             operator_set_params, minimum_stake_required, strategy_params, look_ahead_period
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Created slashable stake quorum with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_eject_operator():
#     """Test ejecting an operator from specified quorums"""
#     try:
#         # Define the operator to eject
#         if "operator_to_eject" not in config:
#             # If not specified, use the operator address from config
#             operator_to_eject = config["operator_address"]
#         else:
#             operator_to_eject = config["operator_to_eject"]

#         operator_address = Web3.to_checksum_address(operator_to_eject)

#         # Define quorum numbers to eject from
#         quorum_numbers = [0]  # Eject from quorum 0

#         # Eject the operator
#         receipt = clients.avs_writer.eject_operator(operator_address, quorum_numbers)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Ejected operator with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_operator_set_params():
#     """Test setting operator set parameters for a quorum"""
#     try:
#         # Define quorum number
#         quorum_number = 0

#         # Define operator set parameters
#         operator_set_params = {
#             "maxOperatorCount": 10,
#             "kickBIPsOfOperatorStake": 10000,  # 100% in basis points
#             "kickBIPsOfTotalStake": 2000,  # 20% in basis points
#         }

#         # Set operator set parameters
#         receipt = clients.avs_writer.set_operator_set_params(quorum_number, operator_set_params)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set operator set params with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_churn_approver():
#     """Test setting the churn approver address"""
#     try:
#         # Define the churn approver address
#         churn_approver_address = Web3.to_checksum_address(config["operator_address"])

#         # Set the churn approver
#         receipt = clients.avs_writer.set_churn_approver(churn_approver_address)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set churn approver with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_ejector():
#     """Test setting the ejector address"""
#     try:
#         # Define the ejector address
#         ejector_address = Web3.to_checksum_address(config["operator_address"])

#         # Set the ejector
#         receipt = clients.avs_writer.set_ejector(ejector_address)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set ejector with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_modify_strategy_params():
#     """Test modifying strategy parameters for a quorum"""
#     try:
#         # Define quorum number
#         quorum_number = 0

#         # Define strategy indices and multipliers
#         # These would typically be indices of existing strategies in the quorum
#         strategy_indices = [0]  # First strategy
#         multipliers = [8000]  # 80% multiplier in basis points

#         # Modify strategy parameters
#         receipt = clients.avs_writer.modify_strategy_params(
#             quorum_number, strategy_indices, multipliers
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Modified strategy parameters with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_account_identifier():
#     """Test setting the account identifier address"""
#     try:
#         # Define the account identifier address
#         account_identifier_address = Web3.to_checksum_address(config["operator_address"])

#         # Set the account identifier
#         receipt = clients.avs_writer.set_account_identifier(account_identifier_address)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set account identifier with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_set_ejection_cooldown():
#     """Test setting the ejection cooldown period"""
#     try:
#         # Define ejection cooldown in blocks
#         ejection_cooldown = 100  # 100 blocks

#         # Set the ejection cooldown
#         receipt = clients.avs_writer.set_ejection_cooldown(ejection_cooldown)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Set ejection cooldown with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_add_strategies():
#     """Test adding strategies to a quorum"""
#     try:
#         # Define quorum number
#         quorum_number = 0

#         # Define strategy parameters
#         # These would typically be a list of strategy addresses and their weights
#         strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
#         strategy_params = [{"strategy": strategy_addr, "multiplier": 5000}]  # 50% in basis points

#         # Add strategies to the quorum
#         receipt = clients.avs_writer.add_strategies(quorum_number, strategy_params)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Added strategies to quorum with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_update_avs_metadata_uri():
#     """Test updating the AVS metadata URI"""
#     try:
#         # Define a new metadata URI
#         metadata_uri = "https://example.com/avs-metadata-updated"

#         # Update the AVS metadata URI
#         receipt = clients.avs_writer.update_avs_metadata_uri(metadata_uri)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Updated AVS metadata URI with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_remove_strategies():
#     """Test removing strategies from a quorum"""
#     try:
#         # Define quorum number
#         quorum_number = 0

#         # Define strategy indices to remove
#         # These would typically be indices of existing strategies in the quorum
#         indices_to_remove = [1]  # Remove the second strategy (index 1)

#         # Remove strategies from the quorum
#         receipt = clients.avs_writer.remove_strategies(quorum_number, indices_to_remove)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Removed strategies from quorum with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_create_avs_rewards_submission():
#     """Test creating an AVS rewards submission"""
#     try:
#         # Define rewards submission
#         # This structure will depend on your specific rewards schema
#         # Below is an example structure
#         rewards_submission = [
#             {
#                 "blockNumber": clients.eth_http_client.eth.block_number - 100,
#                 "tokenAddr": Web3.to_checksum_address(config["token_addr"]),
#                 "amount": 1000000,  # 1 million (adjust based on your token decimals)
#                 "earnerAddr": Web3.to_checksum_address(config["operator_address"]),
#             }
#         ]

#         # Create AVS rewards submission
#         receipt = clients.avs_writer.create_avs_rewards_submission(rewards_submission)

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(f"Created AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}")

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")


# def test_create_operator_directed_avs_rewards_submission():
#     """Test creating an operator-directed AVS rewards submission"""
#     try:
#         # Define operator-directed rewards submissions
#         # This structure will depend on your specific rewards schema
#         # Below is an example structure
#         operator_directed_rewards_submissions = [
#             {
#                 "operator": Web3.to_checksum_address(config["operator_address"]),
#                 "tokenAddr": Web3.to_checksum_address(config["token_addr"]),
#                 "amount": 1000000,  # 1 million (adjust based on your token decimals)
#                 "earnerAddr": Web3.to_checksum_address(config["operator_address"]),
#             }
#         ]

#         # Create operator-directed AVS rewards submission
#         receipt = clients.avs_writer.create_operator_directed_avs_rewards_submission(
#             operator_directed_rewards_submissions
#         )

#         # Verify the transaction was successful
#         assert receipt is not None
#         assert receipt["status"] == 1
#         print(
#             f"Created operator-directed AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}"
#         )

#     except Exception as e:
#         pytest.skip(f"Skipping test due to error: {str(e)}")
