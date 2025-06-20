from dataclasses import dataclass
from typing import Any, Dict, List

from web3 import Web3
from web3.types import ChecksumAddress

from eigensdk.crypto.bls.attestation import G1Point, G2Point, Signature


@dataclass
class Operator:
    address: ChecksumAddress
    earnings_receiver_address: ChecksumAddress
    staker_opt_out_window_blocks: int
    metadata_url: str
    allocation_delay: int = 50
    delegation_approver_address: ChecksumAddress = Web3.to_checksum_address(
        "0x0000000000000000000000000000000000000000"
    )


@dataclass
class OperatorPubkeys:
    g1_pub_key: G1Point
    g2_pub_key: G2Point


@dataclass
class OperatorInfo:
    socket: str
    pub_keys: OperatorPubkeys


@dataclass
class OperatorAvsState:
    operator_id: bytes
    operator_info: OperatorInfo
    stake_per_quorum: Dict[int, int]
    block_number: int


@dataclass
class QuorumAvsState:
    quorum_number: int
    total_stake: int
    agg_pub_key_g1: G1Point
    block_number: int


@dataclass
class OperatorStateRetrieverCheckSignaturesIndices:
    non_signer_quorum_bitmap_indices: List[int]
    quorum_apk_indices: List[int]
    total_stake_indices: List[int]
    non_signer_stake_indices: List[List[int]]


@dataclass
class SignedTaskResponseDigest:
    task_response: Any
    bls_signature: Signature
    operator_id: int


@dataclass
class OperatorStateRetrieverOperator:
    operator: ChecksumAddress
    operator_id: bytes
    stake: int


@dataclass
class StakeRegistryTypesStrategyParams:
    strategy: str
    multiplier: int


@dataclass
class StakeRegistryTypesStakeUpdate:
    update_block_number: int
    next_update_block_number: int
    stake: int


@dataclass
class BLSApkRegistryTypesApkUpdate:
    apk_hash: bytes
    update_block_number: int
    next_update_block_number: int
