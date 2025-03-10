from eth_abi import encode_abi
from eth_utils import to_bytes


def abi_encode_registration_params(
    registration_type: int,
    socket: str,
    pubkey_reg_params: tuple[
        tuple[int, int], tuple[int, int], tuple[list[int], list[int]]
    ],
) -> bytes:

    type_str = (
        "(uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"
    )

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
    pubkey_reg_params: tuple[
        tuple[int, int], tuple[int, int], tuple[list[int], list[int]]
    ],
) -> bytes:

    type_str = "(uint256,uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"

    data = (
        operator_id,
        registration_type,
        socket,
        (pubkey_reg_params[0], pubkey_reg_params[1], pubkey_reg_params[2]),
    )

    encoded = encode_abi([type_str], [data])
    return encoded[32:]
