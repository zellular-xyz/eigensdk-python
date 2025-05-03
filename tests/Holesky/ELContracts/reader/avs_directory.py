from tests.builder import holesky_el_reader
from eth_typing import Address
from web3 import Web3


def test_is_operator_registered_with_avs():
    return holesky_el_reader.is_operator_registered_with_avs(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_calculate_operator_avs_registration_digest_hash():
    return holesky_el_reader.calculate_operator_avs_registration_digest_hash(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        Web3.to_bytes(hexstr="0x121212").rjust(32, b"\0"),
        128,
    )
