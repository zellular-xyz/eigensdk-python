from dataclasses import dataclass
from typing import Dict, Any, List
from tests.builder import holesky_avs_registry_writer
from eth_typing import Address
from eigensdk.crypto.bls.attestation import BLSKeyPair, new_private_key
import ecdsa


def test_update_stakes_of_entire_operator_set_for_quorums():
    # Sample operators for each quorum
    operators_per_quorum = [
        # Operators for quorum 0
        [
            "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
            "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        ],
        # Operators for quorum 1
        [
            "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
            "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        ],
    ]

    # Corresponding quorum numbers - encode as bytes
    quorum_numbers = bytes([0, 1])

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
        operators_per_quorum=operators_per_quorum,
        quorum_numbers=quorum_numbers,
        wait_for_receipt=False,
    )


def test_register_operator_with_churn():
    # Generate a new BLS key pair for testing
    bls_private_key = new_private_key()
    bls_key_pair = BLSKeyPair(bls_private_key)

    # Create operator ECDSA private key from the environment variable
    operator_ecdsa_private_key = ecdsa.SigningKey.from_string(
        bytes.fromhex(PRIVATE_KEY[2:] if PRIVATE_KEY.startswith("0x") else PRIVATE_KEY),
        curve=ecdsa.SECP256k1,
    )

    # For testing, we'll use the same private key for churn approver
    # In a real scenario, this would be a different key belonging to the churn approver
    churn_approval_ecdsa_private_key = operator_ecdsa_private_key

    # Sample quorum numbers to register for
    quorum_numbers = [0, 1]  # Register for quorums 0 and 1

    # Sample quorum numbers and operators to kick
    quorum_numbers_to_kick = [0, 1]
    operators_to_kick = [
        "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
    ]

    # Sample socket address
    socket = "localhost:9000"  # Example socket address

    # Register the operator with churn
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.register_operator_with_churn(
        operator_ecdsa_private_key=operator_ecdsa_private_key,
        churn_approval_ecdsa_private_key=churn_approval_ecdsa_private_key,
        bls_key_pair=bls_key_pair,
        quorum_numbers=quorum_numbers,
        quorum_numbers_to_kick=quorum_numbers_to_kick,
        operators_to_kick=operators_to_kick,
        socket=socket,
        wait_for_receipt=False,
    )


def test_update_stakes_of_operator_subset_for_all_quorums():
    # Sample list of operator addresses to update stakes for
    operators = [
        "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
    ]

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(
        operators=operators, wait_for_receipt=False
    )


def test_deregister_operator():
    # Sample quorum numbers to deregister from
    quorum_numbers = [0, 1]  # Deregister from quorums 0 and 1

    # Create a dummy BN254G1Point (this parameter appears unused in the implementation)
    pubkey = BN254G1Point(1, 2)  # Example values

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.deregister_operator(
        quorum_numbers=quorum_numbers, pubkey=pubkey, wait_for_receipt=False
    )


def test_update_socket():
    # Sample socket address
    socket = "localhost:9001"  # New socket address

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.update_socket(socket=socket, wait_for_receipt=False)


def test_create_total_delegated_stake_quorum():
    # Sample operator set parameters
    operator_set_params = {
        "maxOperatorCount": 10,  # Maximum number of operators in the set
        "kickBIPsOfOperatorStake": 500,  # BIPs (0.5%) of operator's stake to kick
        "kickBIPsOfTotalStake": 100,  # BIPs (0.1%) of total stake to kick
    }

    # Sample minimum stake required (e.g., 100 tokens with 18 decimals)
    minimum_stake_required = 100 * 10**18

    # Sample strategy parameters
    strategy_params = [
        {
            "strategy": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",  # Strategy contract address
            "multiplier": 10000,  # Weight multiplier for this strategy (1.0 = 10000)
        },
        {
            "strategy": "0xe03D546ADa84B5624b50aA22Ff8B87baDEf44ee2",  # Another strategy contract
            "multiplier": 20000,  # Weight multiplier of 2.0
        },
    ]

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.create_total_delegated_stake_quorum(
        operator_set_params=operator_set_params,
        minimum_stake_required=minimum_stake_required,
        strategy_params=strategy_params,
        wait_for_receipt=False,
    )


def test_create_slashable_stake_quorum():
    # Sample operator set parameters
    operator_set_params = {
        "maxOperatorCount": 10,  # Maximum number of operators in the set
        "kickBIPsOfOperatorStake": 500,  # BIPs (0.5%) of operator's stake to kick
        "kickBIPsOfTotalStake": 100,  # BIPs (0.1%) of total stake to kick
    }

    # Sample minimum stake required (e.g., 100 tokens with 18 decimals)
    minimum_stake_required = 100 * 10**18

    # Sample strategy parameters
    strategy_params = [
        {
            "strategy": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",  # Strategy contract address
            "multiplier": 10000,  # Weight multiplier for this strategy (1.0 = 10000)
        },
        {
            "strategy": "0xe03D546ADa84B5624b50aA22Ff8B87baDEf44ee2",  # Another strategy contract
            "multiplier": 20000,  # Weight multiplier of 2.0
        },
    ]

    # Sample look ahead period (in blocks)
    look_ahead_period = 100  # Number of blocks to look ahead for slashing

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.create_slashable_stake_quorum(
        operator_set_params=operator_set_params,
        minimum_stake_required=minimum_stake_required,
        strategy_params=strategy_params,
        look_ahead_period=look_ahead_period,
        wait_for_receipt=False,
    )


def test_eject_operator():
    # Sample operator address to eject
    operator_address = "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"

    # Sample quorum numbers to eject from
    quorum_numbers = [0, 1]  # Eject from quorums 0 and 1

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.eject_operator(
        operator_address=operator_address, quorum_numbers=quorum_numbers, wait_for_receipt=False
    )


def test_set_operator_set_params():
    # Sample quorum number to update parameters for
    quorum_number = 0  # Update parameters for quorum 0

    # Sample operator set parameters
    operator_set_params = {
        "maxOperatorCount": 15,  # New maximum number of operators in the set
        "kickBIPsOfOperatorStake": 600,  # New BIPs (0.6%) of operator's stake to kick
        "kickBIPsOfTotalStake": 120,  # New BIPs (0.12%) of total stake to kick
    }

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_operator_set_params(
        quorum_number=quorum_number, operator_set_params=operator_set_params, wait_for_receipt=False
    )


def test_set_churn_approver():
    # Sample churn approver address
    churn_approver_address = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_churn_approver(
        churn_approver_address=churn_approver_address, wait_for_receipt=False
    )


def test_set_ejector():
    # Sample ejector address
    ejector_address = "0x7F9a98e2F5f5fC3f1D768A894A5e53bb9471D615"

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_ejector(
        ejector_address=ejector_address, wait_for_receipt=False
    )


def test_set_account_identifier():
    # Sample account identifier address
    account_identifier_address = "0x2E645469f354BB4F5c8a05B3b30A929361cf77eC"

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_account_identifier(
        account_identifier_address=account_identifier_address, wait_for_receipt=False
    )


def test_register_operator():
    # Generate a new BLS key pair for testing
    bls_private_key = new_private_key()
    bls_key_pair = BLSKeyPair(bls_private_key)

    # Create an ECDSA private key from the environment variable
    # Note: In a real test, you would generate a new one or use a test key
    operator_ecdsa_private_key = ecdsa.SigningKey.from_string(
        bytes.fromhex(PRIVATE_KEY[2:] if PRIVATE_KEY.startswith("0x") else PRIVATE_KEY),
        curve=ecdsa.SECP256k1,
    )

    # Sample quorum numbers
    quorum_numbers = [0, 1]  # Register for quorums 0 and 1

    # Sample socket address
    socket = "localhost:9000"  # Example socket address

    # Register the operator
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.register_operator(
        operator_ecdsa_private_key=operator_ecdsa_private_key,
        bls_key_pair=bls_key_pair,
        quorum_numbers=quorum_numbers,
        socket=socket,
        wait_for_receipt=False,
    )
