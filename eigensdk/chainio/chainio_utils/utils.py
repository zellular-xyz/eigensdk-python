from typing import Tuple
from eigensdk.crypto.bls.attestation import G1Point, G2Point
from decimal import Decimal


class BN254G1Point:
    def __init__(self, x: int, y: int):
        self.X = x
        self.Y = y


class BN254G2Point:
    def __init__(self, x: Tuple[int, int], y: Tuple[int, int]):
        self.X = x
        self.Y = y


def convert_bn254_geth_to_gnark(input_point: BN254G1Point) -> G1Point:
    return G1Point(input_point.X, input_point.Y).to_g1_affine()


def convert_to_bn254_g1_point(input_point: G1Point) -> BN254G1Point:
    return BN254G1Point(
        x=input_point.X.to_big_int(),  # Assuming method exists
        y=input_point.Y.to_big_int(),
    )


def convert_to_bn254_g2_point(input_point: G2Point) -> BN254G2Point:
    return BN254G2Point(
        x=(input_point.X.A1.to_big_int(), input_point.X.A0.to_big_int()),
        y=(input_point.Y.A1.to_big_int(), input_point.Y.A0.to_big_int()),
    )


def abi_encode_registration_params(
    registration_type: int,
    socket: str,
    pubkey_reg_params: tuple[tuple[int, int], tuple[int, int], tuple[list[int], list[int]]],
) -> bytes:

    type_str = "(uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"

    data = (
        registration_type,
        socket,
        (pubkey_reg_params[0], pubkey_reg_params[1], pubkey_reg_params[2]),
    )

    encoded = encode_abi([type_str], [data])
    return encoded[32:]  # Remove initial offset pointer


def abi_encode_operator_avs_registration_params(
    operator_id: int,
    registration_type: int,
    socket: str,
    pubkey_reg_params: tuple[tuple[int, int], tuple[int, int], tuple[list[int], list[int]]],
) -> bytes:

    type_str = (
        "(uint256,uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"
    )

    data = (
        operator_id,
        registration_type,
        socket,
        (pubkey_reg_params[0], pubkey_reg_params[1], pubkey_reg_params[2]),
    )

    encoded = encode_abi([type_str], [data])
    return encoded[32:]


def bitmap_to_quorum_ids(bitmap: int, max_number_of_quorums: int = 64) -> list[int]:

    quorum_ids = []

    # Loop through each bit position in the bitmap
    for i in range(max_number_of_quorums):
        # Check if the bit at position i is set (1)
        if (bitmap & (1 << i)) != 0:
            quorum_ids.append(i)

    return quorum_ids


def remove_duplicate_strategies(strategies):
    """
    Removes duplicates from the given list of strategy addresses.

    Args:
        strategies: List of strategy addresses as strings

    Returns:
        List of unique strategy addresses, sorted and with duplicates removed
    """
    if not strategies:
        return []

    # Sort the strategies lexicographically
    sorted_strategies = sorted(strategies)

    # Create a new list for unique strategies
    unique_strategies = [sorted_strategies[0]]
    last_element = sorted_strategies[0]

    # Iterate through the sorted list, adding each unique strategy
    for strategy in sorted_strategies[1:]:
        if strategy == last_element:
            continue
        last_element = strategy
        unique_strategies.append(strategy)

    return unique_strategies
