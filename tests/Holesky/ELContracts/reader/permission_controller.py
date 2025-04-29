from tests.builder import holesky_el_reader
from eth_typing import Address
from web3 import Web3

def test_can_call():
    return holesky_el_reader.can_call(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        appointee_address=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        target=Address("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"),
        selector=Web3.keccak(text="someFunction()")[:4]  # Example function selector (first 4 bytes of keccak hash)
    )



def test_list_appointees():
    return holesky_el_reader.list_appointees(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        target=Address("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"),
        selector=Web3.keccak(text="someFunction()")[:4]  # Example function selector (first 4 bytes of keccak hash)
    )



def test_list_appointee_permissions():
    return holesky_el_reader.list_appointee_permissions(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        appointee_address=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")
    )


def test_list_pending_admins():
    return holesky_el_reader.list_pending_admins(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )



def test_list_admins():
    return holesky_el_reader.list_admins(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_is_pending_admin():
    return holesky_el_reader.is_pending_admin(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        pending_admin_address=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")
    )


def test_is_admin():
    return holesky_el_reader.is_admin(
        account_address=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        admin_address=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")
    )