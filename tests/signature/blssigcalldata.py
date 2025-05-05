import json
import os
import random
from dataclasses import dataclass
from typing import Dict, List, Tuple

from eth_abi import encode
from eth_typing import HexStr
from eth_utils import keccak, to_bytes
from web3 import Web3
from web3.contract import Contract

from eigensdk.crypto.bls.attestation import (
    KeyPair,
    Signature,
    gen_random_bls_keys,
)
from eigensdk.crypto.bn256 import utils as bn_utils

###############################################################################
# ── CONFIG – fill in to target your deployment  ──────────────────────────────
###############################################################################

RPC_URL = os.environ.get("RPC_URL", "https://holesky.infura.io/v3/889a5bab533a43e993049f577a2c136b")
REGISTRY_COORDINATOR = "0xC908fAFAE29B5C9F0b5E0Da1d3025b8d6D42bfa0"
OPER_STATE_RETRIEVER = "0xB4baAfee917fb4449f5ec64804217bccE9f46C67"
AGGREGATOR_EOA = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"

# ---------------------------------------------------------------------------

TASK_RESPONSE_TUPLE_TYPE = "(uint256 dummy)"
example_task_response = (123,)

# ---------------------------------------------------------------------------

w3 = Web3(Web3.HTTPProvider(RPC_URL))
assert w3.is_connected(), "Cannot reach RPC – check RPC_URL"

###############################################################################
# ── Helper functions ─────────────────────────────────────────────────────────
###############################################################################


def fp_to_int(fp) -> int:
    return int(fp.getStr())


def g1_tuple(pt):
    pt.normalize()
    return fp_to_int(pt.x), fp_to_int(pt.y)


def g2_tuple(pt):
    pt.normalize()
    return (
        (fp_to_int(pt.x.c0), fp_to_int(pt.x.c1)),
        (fp_to_int(pt.y.c0), fp_to_int(pt.y.c1)),
    )


def pubkey_hash_from_g1(pt) -> bytes:
    return keccak(encode(["uint256", "uint256"], g1_tuple(pt)))


###############################################################################
# ── Dataclasses ──────────────────────────────────────────────────────────────
###############################################################################


@dataclass
class OperatorInfo:
    operator_id: bytes
    keypair: KeyPair
    stake: int


@dataclass
class PrepResult:
    msg_hash: bytes
    quorum_numbers: bytes
    reference_block: int
    params_tuple: tuple
    call_data_dict: dict


###############################################################################
# ── Demo operator set ───────────────────────────────────────────────────────
###############################################################################

random.seed(42)
OPERATORS_RAW = json.loads(
    """[
        {"id":"0x0d84f2cfff72db8b927c27d01ae90e73bf453be3","socket":"http://15.204.30.246:6001","stake":"33275521608384169292"},
        {"id":"0x121298c65a62d6c8a14ee44778bbe38ebea8c869","socket":"http://15.235.41.237:6001","stake":"1124060129820254450"},
        {"id":"0x37d5077434723d0ec21d894a52567cbe6fb2c3d8","socket":"http://141.144.201.104:6001","stake":"1895336718771218298"},
        {"id":"0x390ab6a8da334f2ac5d58513b583aa47fe00a716","socket":"http://116.251.192.226:13816","stake":"9959487765319163"},
        {"id":"0x3eaa1c283dbf13357257e652649784a4cc08078c","socket":"http://5.161.230.186:6001","stake":"2974982461847618543"},
        {"id":"0x4550f589086cdb5fe39bd2e6a2782e2a65a292de","socket":"http://161.97.140.52:9000","stake":"0"},
        {"id":"0x747b80a1c0b0e6031b389e3b7eaf9b5f759f34ed","socket":"http://172.86.109.14:6001","stake":"4776064595081970865"},
        {"id":"0x906585f83fa7d29b96642aa8f7b4267ab42b7b6c","socket":"http://37.27.41.237:6001","stake":"1980028561960706956"},
        {"id":"0x93d89ade53b8fcca53736be1a0d11d342d71118b","socket":"http://89.106.206.214:6001","stake":"1005776726904316428"},
        {"id":"0xa00a522975575f70180e6ba0466896786998f00e","socket":"http://[168.119.4.116:4444]","stake":"1981035445664413064"},
        {"id":"0xb6460a5c1ff8fd412f11c6c19e66f1449f13332d","socket":"http://88.198.2.58:1515","stake":"31774844676523928611"},
        {"id":"0xc5211f55ef0e06659a92e7c3a7fd675cccb58ce6","socket":"http://[ip:port]","stake":"1489394766091141560"},
        {"id":"0xd216ccb2d95809957a3128824dddb136d90dfde7","socket":"http://213.239.206.135:9091","stake":"1036678674083155839644"},
        {"id":"0xe390f8917306d3184d0a35160909998032d79de7","socket":"http://[ip:port]","stake":"0"},
        {"id":"0xe3b520f525b57be060f2c7b9ca0ea98a2dc4500b","socket":"http://176.9.7.122:8241","stake":"1686037489182236898275"}
    ]"""
)

operator_info: Dict[str, OperatorInfo] = {}
for entry in OPERATORS_RAW:
    op_id_bytes32 = to_bytes(hexstr=entry["id"]).rjust(32, b"\x00")
    kp = gen_random_bls_keys()
    operator_info[entry["id"].lower()] = OperatorInfo(
        operator_id=op_id_bytes32,
        keypair=kp,
        stake=int(entry["stake"]),
    )

ALL_OP_IDS = list(operator_info.keys())
SIGNER_IDS = random.sample(ALL_OP_IDS, int(0.7 * len(ALL_OP_IDS)))
NON_SIGNER_IDS = [oid for oid in ALL_OP_IDS if oid not in SIGNER_IDS]

###############################################################################
# ── Step 1: sign message & aggregate signers' sig (σ)  ──────────────────────
###############################################################################

MESSAGE = b"Zellular"
attestations: List[Signature] = []
for opid in SIGNER_IDS:
    kp = operator_info[opid].keypair
    attestations.append(kp.sign_message(MESSAGE))

sigma_g1 = attestations[0]
for sig in attestations[1:]:
    sigma_g1 += sig

###############################################################################
# ── Step 2: aggregate ALL operators' G2 pubkeys (apkG2)  ────────────────────
###############################################################################
apk_g2 = operator_info[ALL_OP_IDS[0]].keypair.pub_g2
for opid in ALL_OP_IDS[1:]:
    apk_g2 += operator_info[opid].keypair.pub_g2

###############################################################################
# ── Step 3: build Non‑signer arrays; fetch historical indices  ──────────────
###############################################################################
quorum_numbers = b"\x00"
reference_block = w3.eth.block_number - 1

# ── 3a  Non‑signer pubkeys sorted by pubkey‑hash
non_signer_pubkeys_sorted = sorted(
    [operator_info[oid].keypair.pub_g1 for oid in NON_SIGNER_IDS],
    key=pubkey_hash_from_g1,
)

# ── 3b  Call OperatorStateRetriever to get all four index arrays
retriever_abi = json.load(open("OperatorStateRetriever.json"))  # ensure ABI present
retriever: Contract = w3.eth.contract(address=OPER_STATE_RETRIEVER, abi=retriever_abi)
non_signer_ids_bytes32 = [operator_info[oid].operator_id for oid in NON_SIGNER_IDS]
indices = retriever.functions.getCheckSignaturesIndices(
    REGISTRY_COORDINATOR,
    reference_block,
    quorum_numbers,
    non_signer_ids_bytes32,
).call()

(
    non_signer_quorum_bitmap_indices,
    quorum_apk_indices,
    total_stake_indices,
    non_signer_stake_indices,
) = indices  # exact ordering per Solidity struct

# ── 3c  Fetch quorum APKs (G1) for each quorum via Registry
quorum_apks = [
    sum(
        [operator_info[oid].keypair.pub_g1 for oid in ALL_OP_IDS[1:]],
        operator_info[ALL_OP_IDS[0]].keypair.pub_g1,
    )
]

###############################################################################
# ── Step 4: hash the message as contract will do (abi.encode)  ──────────────
###############################################################################
encoded_task_response = encode([TASK_RESPONSE_TUPLE_TYPE], [example_task_response])
msg_hash = keccak(encoded_task_response)

###############################################################################
# ── Step 5: final struct & user‑friendly dict  ──────────────────────────────
###############################################################################
non_signer_pubkeys_tuples = [g1_tuple(p) for p in non_signer_pubkeys_sorted]
quorum_apks_tuples = [g1_tuple(p) for p in quorum_apks]

params_tuple = (
    non_signer_quorum_bitmap_indices,
    non_signer_pubkeys_tuples,
    quorum_apks_tuples,
    g2_tuple(apk_g2),
    g1_tuple(sigma_g1),
    quorum_apk_indices,
    total_stake_indices,
    non_signer_stake_indices,
)

call_data_dict = {
    "msgHash": Web3.to_hex(msg_hash),
    "quorumNumbers": quorum_numbers.hex(),
    "referenceBlockNumber": reference_block,
    "NonSignerStakesAndSignature": {
        "nonSignerQuorumBitmapIndices": non_signer_quorum_bitmap_indices,
        "nonSignerPubkeys": [tuple(map(hex, t)) for t in non_signer_pubkeys_tuples],
        "quorumApks": [tuple(map(hex, t)) for t in quorum_apks_tuples],
        "apkG2": [[hex(x) for x in row] for row in g2_tuple(apk_g2)],
        "sigma": tuple(map(hex, g1_tuple(sigma_g1))),
        "quorumApkIndices": quorum_apk_indices,
        "totalStakeIndices": total_stake_indices,
        "nonSignerStakeIndices": non_signer_stake_indices,
    },
}

if __name__ == "__main__":
    print("Prepared calldata for checkSignatures:\n")
    print(json.dumps(call_data_dict, indent=2))
