from tests.builder import holesky_el_reader
from eth_typing import Address


def test_get_operator_shares():
    return holesky_el_reader.get_operator_shares(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        [Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")],
    )


def test_is_operator_registered():
    return holesky_el_reader.is_operator_registered(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_staker_shares():
    return holesky_el_reader.get_staker_shares(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_delegated_operator():
    # Test without specifying block number
    return holesky_el_reader.get_delegated_operator(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_operator_details():
    operator = {"Address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"}
    return holesky_el_reader.get_operator_details(operator)


def test_get_operator_shares_in_strategy():
    return holesky_el_reader.get_operator_shares_in_strategy(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_calculate_delegation_approval_digest_hash():
    return holesky_el_reader.calculate_delegation_approval_digest_hash(
        staker=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),  # Staker address
        operator=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),  # Operator address
        delegation_approver=Address(
            "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"
        ),  # Delegation approver
        approver_salt=b"\x00" * 32,  # Sample approver salt
        expiry=1735689600,  # Sample expiry timestamp
    )


def test_get_operators_shares():
    return holesky_el_reader.get_operators_shares(
        operator_addresses=[
            Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
            Address("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"),
        ],
        strategy_addresses=[
            Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
            Address("0xe03D546ADa84B5624b50aA22Ff8B87baDEf44ee2"),
        ],
    )


def test_get_delegation_approver_salt_is_spent():
    return holesky_el_reader.get_delegation_approver_salt_is_spent(
        delegation_approver=Address("0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"),
        approver_salt=b"\x00" * 32,  # 32 bytes of zeros as sample salt
    )


def test_get_pending_withdrawal_status():
    # Using a sample withdrawal root (32 bytes of zeros)
    return holesky_el_reader.get_pending_withdrawal_status(withdrawal_root=b"\x00" * 32)


def test_get_cumulative_withdrawals_queued():
    return holesky_el_reader.get_cumulative_withdrawals_queued(
        staker=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )
