from tests.builder import holesky_el_writer
from eigensdk.crypto.bls.attestation import BLSKeyPair, new_private_key
from eth_typing import Address
import time


def test_deposit_erc20_into_strategy():
    strategy_addr = "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"
    amount = 100 * 10**18
    return holesky_el_writer.deposit_erc20_into_strategy(
        strategy_addr=strategy_addr,
        amount=amount,
        wait_for_receipt=False
    )

