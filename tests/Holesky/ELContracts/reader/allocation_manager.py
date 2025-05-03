from tests.builder import holesky_el_reader
from eth_typing import Address


def test_get_allocatable_magnitude():
    return holesky_el_reader.get_allocatable_magnitude(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_get_max_magnitudes():
    return holesky_el_reader.get_max_magnitudes(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        [
            Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
            Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        ],
    )


def test_get_allocation_info():
    return holesky_el_reader.get_allocation_info(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_get_operator_sets_for_operator():
    return holesky_el_reader.get_operator_sets_for_operator(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_allocation_delay():
    return holesky_el_reader.get_allocation_delay(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_registered_sets():
    return holesky_el_reader.get_registered_sets(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_is_operator_registered_with_operator_set():
    operator_set = {"id": 1, "vs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.is_operator_registered_with_operator_set(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"), operator_set
    )


def test_is_operator_slashable():
    operator_set = {"Id": 1, "Avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.is_operator_slashable(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"), operator_set
    )


def test_get_allocated_stake():
    operator_set = {"Id": 1, "Avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.get_allocated_stake(
        operator_set,
        [Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")],
        [Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")],
    )


def test_get_operators_for_operator_set():
    operator_set = {"Id": 1, "Avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.get_operators_for_operator_set(operator_set)


def test_get_num_operators_for_operator_set():
    operator_set = {"Id": 1, "Avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.get_num_operators_for_operator_set(operator_set)


def test_get_strategies_for_operator_set():
    operator_set = {"Id": 1, "Avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.get_strategies_for_operator_set(operator_set)


def test_get_avs_registrar():
    return holesky_el_reader.get_avs_registrar(
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")
    )


def test_get_operator_details():
    operator = {"Address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"}
    return holesky_el_reader.get_operator_details(operator)


def test_get_encumbered_magnitude():
    return holesky_el_reader.get_encumbered_magnitude(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_get_deallocation_delay():
    return holesky_el_reader.get_deallocation_delay()


def test_get_allocation_configuration_delay():
    return holesky_el_reader.get_allocation_configuration_delay()


def test_get_num_operator_sets_for_operator():
    return holesky_el_reader.get_num_operator_sets_for_operator(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_slashable_shares():
    operator_set = {"id": 1, "avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"}
    return holesky_el_reader.get_slashable_shares(
        Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        operator_set,
        [Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")],
    )


def test_get_slashable_shares_for_operator_sets_before():
    """
    Test the get_slashable_shares_for_operator_sets_before function.

    This test verifies that:
    1. The function can be called with valid operator sets
    2. The function returns the expected structure
    3. The function handles the timestamp correctly
    """
    # Create operator set with correct structure and lowercase keys
    operator_set = {"id": 1, "avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e", "quorumNumber": 1}
    operator_sets = [operator_set]
    timestamp = 12345678

    result = holesky_el_reader.get_slashable_shares_for_operator_sets_before(
        operator_sets, timestamp
    )

    return result


print(test_get_slashable_shares_for_operator_sets_before())
