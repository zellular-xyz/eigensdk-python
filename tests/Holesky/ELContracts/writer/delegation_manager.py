from tests.builder import holesky_el_writer
from eigensdk.crypto.bls.attestation import KeyPair, new_private_key
from eth_typing import Address
import time
from web3 import Web3
from eigensdk._types import Operator


def test_register_as_operator():
    # Create a sample Operator object
    operator = Operator(
        address="0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",  # Add operator's own address
        delegation_approver_address="0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        allocation_delay=86400,  # 1 day in seconds
        metadata_url="https://example.com/operator-metadata.json",
    )

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_el_writer.register_as_operator(operator=operator, wait_for_receipt=False)


def test_update_operator_details():
    # Create a sample Operator object with both required fields
    operator = Operator(
        delegation_approver_address="0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        allocation_delay=86400,  # 1 day in seconds
        metadata_url="https://example.com/operator-metadata.json",
        address="0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",  # Add operator's own address
    )

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_el_writer.update_operator_details(operator=operator, wait_for_receipt=False)


def test_update_metadata_uri():
    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"

    # Sample metadata URI
    uri = "https://example.com/updated-operator-metadata.json"

    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_el_writer.update_metadata_uri(
        operator_address=operator_address, uri=uri, wait_for_receipt=False
    )
