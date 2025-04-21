from eth_abi import encode
from eth_account.signers.local import LocalAccount
from typing import List
from typing import Tuple, Dict, Any
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.types import Address
from web3.types import TxReceipt

from eigensdk.crypto.bls.attestation import G1Point, G2Point, BLSKeyPair


def nums_to_bytes(nums: List[int]) -> bytes:
    return "".join(map(chr, nums)).encode()


def send_transaction(
    func: ContractFunction, pk_wallet: LocalAccount, eth_http_client: Web3
) -> TxReceipt:
    # try:
    #     eth_http_client.middleware_onion.inject(geth_poa_middleware, layer=0)
    # except Exception:
    #     pass

    try:
        gas_estimate = func.estimate_gas({"from": pk_wallet.address})
    except Exception as e:
        raise Exception(f"Gas estimation failed: {e}")

    current_gas_price = eth_http_client.eth.gas_price

    tx = func.build_transaction(
        {
            "from": pk_wallet.address,
            "gas": gas_estimate,
            "gasPrice": current_gas_price,
            "nonce": eth_http_client.eth.get_transaction_count(pk_wallet.address),
            "chainId": eth_http_client.eth.chain_id,
        }
    )
    signed_tx = eth_http_client.eth.account.sign_transaction(tx, private_key=pk_wallet.key)
    tx_hash = eth_http_client.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = eth_http_client.eth.wait_for_transaction_receipt(tx_hash)
    return receipt


class BN254G1Point:
    def __init__(self, x: int, y: int):
        self.X = x
        self.Y = y


class BN254G2Point:
    def __init__(self, x: Tuple[int, int], y: Tuple[int, int]):
        self.X = x
        self.Y = y


def convert_bn254_geth_to_gnark(input_point: BN254G1Point) -> G1Point:
    return G1Point(input_point.X, input_point.Y)


def convert_to_bn254_g1_point(input_point: G1Point) -> BN254G1Point:
    return BN254G1Point(
        x=int(input_point.x.getStr().decode("utf-8")),
        y=int(input_point.y.getStr().decode("utf-8")),
    )


def convert_to_bn254_g2_point(input_point: G2Point) -> BN254G2Point:
    return BN254G2Point(
        x=(
            int(input_point.getX().get_a().getStr().decode("utf-8")),
            int(input_point.getX().get_b().getStr().decode("utf-8"))
        ),
        y=(
            int(input_point.getY().get_a().getStr().decode("utf-8")),
            int(input_point.getY().get_b().getStr().decode("utf-8"))
        ),
    )


def abi_encode_registration_params(
    registration_type: int,
    socket: str,
    pubkey_reg_params: Dict[str, Any],
) -> bytes:
    """
    ABI encodes the registration parameters.

    Args:
        registration_type: Type of registration
        socket: Socket string
        pubkey_reg_params: Pubkey registration parameters from get_pubkey_registration_params

    Returns:
        ABI encoded registration parameters
    """
    # Extract components from pubkey_reg_params
    signature = pubkey_reg_params["pubkeyRegistrationSignature"]
    g1_pubkey = pubkey_reg_params["pubkeyG1"]
    g2_pubkey = pubkey_reg_params["pubkeyG2"]

    # Format data for encoding
    pubkey_data = (
        (g1_pubkey.X, g1_pubkey.Y),
        (g2_pubkey.X[0], g2_pubkey.X[1]),
        ([g2_pubkey.Y[0], g2_pubkey.Y[1]], [signature.X, signature.Y]),
    )

    type_str = "(uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"

    data = (
        registration_type,
        socket,
        pubkey_data,
    )

    encoded = encode([type_str], [data])
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

    encoded = encode([type_str], [data])
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


def get_pubkey_registration_params(
    eth_client: Web3,
    registry_coordinator_addr: Address,
    operator_address: Address,
    bls_key_pair: BLSKeyPair,
) -> Dict[str, Any]:
    """
    Returns the pubkey registration params for the operator given by `operator_address`.

    Args:
        eth_client: Web3 client
        registry_coordinator_addr: Address of the RegistryCoordinator contract
        operator_address: Address of the operator
        bls_key_pair: BLS key pair for the operator

    Returns:
        Dictionary containing pubkey registration parameters
    """
    # Create contract instance for registry coordinator
    registry_coordinator = eth_client.eth.contract(
        address=registry_coordinator_addr,
        abi=[
            {
                "inputs": [{"internalType": "address", "name": "operator", "type": "address"}],
                "name": "pubkeyRegistrationMessageHash",
                "outputs": [
                    {
                        "components": [
                            {"internalType": "uint256", "name": "X", "type": "uint256"},
                            {"internalType": "uint256", "name": "Y", "type": "uint256"},
                        ],
                        "internalType": "struct BN254.G1Point",
                        "name": "",
                        "type": "tuple",
                    }
                ],
                "stateMutability": "view",
                "type": "function",
            }
        ],
    )

    # Get hashed message to sign
    g1_hashed_msg_to_sign = registry_coordinator.functions.pubkeyRegistrationMessageHash(
        operator_address
    ).call()

    # Convert the hashed message to the format expected by BLSKeyPair
    gnark_msg = convert_bn254_geth_to_gnark(g1_hashed_msg_to_sign)

    # Sign the message
    signed_msg = bls_key_pair.sign_hashed_to_curve_message(gnark_msg)

    # Convert public keys to BN254 format
    g1_pubkey_bn254 = convert_to_bn254_g1_point(bls_key_pair.get_pub_g1())
    g2_pubkey_bn254 = convert_to_bn254_g2_point(bls_key_pair.get_pub_g2())

    # Create and return the pubkey registration params
    pubkey_reg_params = {
        "pubkeyRegistrationSignature": convert_to_bn254_g1_point(signed_msg.g1_point),
        "pubkeyG1": g1_pubkey_bn254,
        "pubkeyG2": g2_pubkey_bn254,
    }

    return pubkey_reg_params
