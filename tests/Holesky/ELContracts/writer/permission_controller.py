from tests.builder import holesky_el_writer
from eigensdk.crypto.bls.attestation import KeyPair, new_private_key
from eth_typing import Address
import time
from web3 import Web3


def test_remove_permission():
    # Sample request dictionary with all required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "appointee_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "target": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "selector": Web3.keccak(text="someFunction()")[:4],  # Example function selector
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.remove_permission(request=request)


def test_new_remove_permission_tx():
    # Sample transaction options (if needed by the method)
    tx_opts = {}

    # Sample request dictionary with all required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "appointee_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "target": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "selector": Web3.keccak(text="someFunction()")[:4],  # Example function selector
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.new_remove_permission_tx(tx_opts=tx_opts, request=request)


def test_set_permission():
    # Sample request dictionary with all required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "appointee_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "target": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
        "selector": Web3.keccak(text="someFunction()")[:4],  # Example function selector
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.set_permission(request=request)


def test_new_accept_admin_tx():
    # Sample transaction options (if needed by the method)
    tx_opts = {}

    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.new_accept_admin_tx(tx_opts=tx_opts, request=request)


def test_accept_admin():
    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.accept_admin(request=request)


def test_add_pending_admin():
    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.add_pending_admin(request=request)


def test_new_remove_admin_tx():
    # Sample transaction options (if needed by the method)
    tx_opts = {}

    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.new_remove_admin_tx(tx_opts=tx_opts, request=request)


def test_remove_admin():
    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.remove_admin(request=request)


def test_new_remove_pending_admin_tx():
    # Sample transaction options (if needed by the method)
    tx_opts = {}

    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.new_remove_pending_admin_tx(tx_opts=tx_opts, request=request)


def test_remove_pending_admin():
    # Sample request dictionary with required fields
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.remove_pending_admin(request=request)


def test_new_add_pending_admin_tx():
    tx_opts = {}
    request = {
        "account_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "admin_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "wait_for_receipt": False,  # Avoid waiting for transaction confirmation
    }

    return holesky_el_writer.new_add_pending_admin_tx(tx_opts=tx_opts, request=request)
