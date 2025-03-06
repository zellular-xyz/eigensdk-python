from eth_abi import encode_abi
from eth_utils import to_bytes

def abi_encode_registration_params(
    registration_type: int,
    socket: str,
    pubkey_reg_params: tuple[tuple[int, int], tuple[int, int], tuple[list[int], list[int]]]
) -> bytes:
    """
    ABI-encodes registration parameters in the same format as the Go implementation.
    
    Args:
        registration_type: Integer representation of RegistrationType enum
        socket: Network socket string
        pubkey_reg_params: Tuple containing three elements:
            - (X: int, Y: int) signature coordinates
            - (X: int, Y: int) G1 public key coordinates
            - (X: list[int], Y: list[int]) G2 public key coordinates (each as list of 2 ints)
    
    Returns:
        ABI-encoded bytes with first 32 bytes removed (offset pointer)
    """
    type_str = '(uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))'
    
    data = (
        registration_type,
        socket,
        (
            pubkey_reg_params[0],  # Signature
            pubkey_reg_params[1],  # G1 public key
            pubkey_reg_params[2]   # G2 public key
        )
    )
    
    encoded = encode_abi([type_str], [data])
    return encoded[32:]  # Remove initial offset pointer


def abi_encode_operator_avs_registration_params(
    operator_id: int,
    registration_type: int,
    socket: str,
    pubkey_reg_params: tuple[tuple[int, int], tuple[int, int], tuple[list[int], list[int]]]
) -> bytes:
    """
    ABI-encodes operator registration parameters with operator ID.
    
    Args:
        operator_id: Unique operator identifier
        See abi_encode_registration_params for other args
    
    Returns:
        ABI-encoded bytes with first 32 bytes removed
    """
    type_str = '(uint256,uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))'
    
    data = (
        operator_id,
        registration_type,
        socket,
        (
            pubkey_reg_params[0],
            pubkey_reg_params[1],
            pubkey_reg_params[2]
        )
    )
    
    encoded = encode_abi([type_str], [data])
    return encoded[32:]