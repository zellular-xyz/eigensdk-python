from typing import List, Tuple, Dict, Any

from eth_abi import encode
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.types import ChecksumAddress
from web3.types import TxReceipt

from eigensdk.contracts import ABIs
from eigensdk.crypto.bls.attestation import G1Point, KeyPair


def nums_to_bytes(nums: List[int]) -> bytes:
    return "".join(map(chr, nums)).encode()


def bitmap_to_quorum_ids(bitmap: int) -> List[int]:
    quorum_ids = []
    for i in range(256):
        if bitmap & (1 << i):
            quorum_ids.append(int(i))
    return quorum_ids


def _send_transaction(
    func: ContractFunction,
    pk_wallet: LocalAccount,
    eth_http_client: Web3,
    gas_limit: int = 10_000_000,
    skip_estimation: bool = True,
) -> TxReceipt:
    if skip_estimation:
        gas_estimate = gas_limit
    else:
        try:
            gas_estimate = func.estimate_gas({"from": pk_wallet.address})
        except Exception as e:
            raise Exception(
                f"""Gas estimation failed: {e}. Consider using
                skip_estimation=True with a manual gas_limit."""
            )

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
    return eth_http_client.eth.wait_for_transaction_receipt(tx_hash)


class Transactor:
    def __init__(
        self,
        pk_wallet: LocalAccount,
        eth_http_client: Web3,
        gas_limit: int = 10_000_000,
        skip_estimation: bool = True,
    ):
        self.pk_wallet = pk_wallet
        self.eth_http_client = eth_http_client
        self.gas_limit = gas_limit
        self.skip_estimation = skip_estimation

    def send(self, func: ContractFunction):
        return _send_transaction(
            func, self.pk_wallet, self.eth_http_client, self.gas_limit, self.skip_estimation
        )


def abi_encode_normal_registration_params(
    registration_type: int,
    socket: str,
    pubkey_reg_params: Dict[str, Tuple[int, int] | Tuple[Tuple[int, int], Tuple[int, int]]],
) -> bytes:
    """
    ABI encode a normal registration tuple:
    (uint8, string, ((uint256, uint256), (uint256, uint256), (uint256[2], uint256[2])))
    """

    # Extract structured values
    pubkey_registration_signature = pubkey_reg_params["pubkeyRegistrationSignature"]  # (x, y)
    pubkey_g1 = pubkey_reg_params["pubkeyG1"]  # (x, y)
    pubkey_g2 = pubkey_reg_params["pubkeyG2"]  # ((x0, x1), (y0, y1))

    # Structure expected by ABI
    pubkey_struct = (
        pubkey_registration_signature,  # (uint256, uint256)
        pubkey_g1,  # (uint256, uint256)
        pubkey_g2,  # ((uint256[2], uint256[2]))
    )

    # Full data
    registration_struct = (
        registration_type,  # uint8
        socket,  # string
        pubkey_struct,  # pubkeyRegParams struct
    )

    abi_type = "(uint8,string,((uint256,uint256),(uint256,uint256),(uint256[2],uint256[2])))"

    encoded = encode([abi_type], [registration_struct])

    return encoded[32:]


def get_pubkey_registration_params(
    eth_client: Web3,
    registry_coordinator_addr: ChecksumAddress,
    operator_address: ChecksumAddress,
    bls_key_pair: KeyPair,
) -> Dict[str, Any]:
    # Create contract instance for registry coordinator
    registry_coordinator = eth_client.eth.contract(
        address=registry_coordinator_addr,
        abi=ABIs.REGISTRY_COORDINATOR_ABI,
    )

    g1_hashed_msg_to_sign = registry_coordinator.functions.pubkeyRegistrationMessageHash(
        operator_address
    ).call()

    g1_hashed_msg_as_point = G1Point(*g1_hashed_msg_to_sign)
    signed_msg = bls_key_pair.sign_hashed_to_curve_message(g1_hashed_msg_as_point)

    # Convert public keys to BN254 format
    pubkey_reg_params = {
        "pubkeyRegistrationSignature": (
            int(signed_msg.getX().getStr()),
            int(signed_msg.getY().getStr()),
        ),
        "pubkeyG1": (
            int(bls_key_pair.pub_g1.getX().getStr()),
            int(bls_key_pair.pub_g1.getY().getStr()),
        ),
        "pubkeyG2": (
            (
                int(bls_key_pair.pub_g2.getX().get_a().getStr()),
                int(bls_key_pair.pub_g2.getX().get_b().getStr()),
            ),
            (
                int(bls_key_pair.pub_g2.getY().get_a().getStr()),
                int(bls_key_pair.pub_g2.getY().get_b().getStr()),
            ),
        ),
    }

    print(pubkey_reg_params)
    return pubkey_reg_params
