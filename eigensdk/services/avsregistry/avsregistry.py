from abc import ABC, abstractmethod
from dataclasses import dataclass
from eigensdk_python.crypto.bls.attestation import KeyPair, G1Point, G2Point, Signature


@dataclass
class OperatorPubkeys:
    # G1 signatures are used to verify signatures onchain (since G1 is cheaper to verify onchain via precompiles)
    g1_pub_key: G1Point
    # G2 is used to verify signatures offchain (signatures are on G1)
    g2_pub_key: G2Point


@dataclass
class OperatorInfo:
    socket: str
    pub_keys: OperatorPubkeys


@dataclass
class OperatorAvsState:
    operator_id: int
    operator_info: OperatorInfo
    # Stake of the operator for each quorum
    stake_per_quorum: list[int, int]
    block_number: int


@dataclass
class QuorumAvsState:
    quorum_number: int
    total_stake: int
    agg_pub_key_g1: G1Point
    block_number: int

@dataclass
class CallOpts:
    # Whether to operate on the pending state or the last known one
    pending: bool
    # Optional the sender address, otherwise the first account is used
    from_address: str
    # Optional the block number on which the call should be performed
    block_number: int
    # Optional the block hash on which the call should be performed
    block_hash: str

    # the field below is for golang. Don't know the proper replacement for it in python
    # Context: context.Context # Network context to support cancellation and timeouts (nil = no timeout)
    def __init__(self, pending:bool=None, from_address:str = None, block_number:int = None, block_hash:str = None):
         self.pending = pending
         self.from_address = from_address
         block_number = block_number
         block_hash = block_hash


@dataclass
class OperatorStateRetrieverCheckSignaturesIndices:
    non_signer_quorum_bitmap_indices: list[int]
    quorum_apk_indices: list[int]
    total_stake_indices: list[int]
    non_signer_stake_indices: list[list[int]]

@dataclass
class SignedTaskResponseDigest:
	task_response: any
	bls_signature: Signature
	operator_id: int


class AvsRegistryService(ABC):
    """
    all the moethods support cancellation through what is called a Context in Go.
    The GetCheckSignaturesIndices should support Context inside CallOpts data class
    """

    @abstractmethod
    async def get_operators_avs_state_at_block(
        quorum_numbers: list[int], block_number: int
    ) -> dict[int, OperatorAvsState]: ...

    @abstractmethod
    async def get_quorums_avs_state_at_block(
        quorum_numbers: list[int], block_number: int
    ) -> dict[int, QuorumAvsState]: ...

    @abstractmethod
    async def get_check_signatures_indices(
        opts: CallOpts,
        reference_block_number: int,
        quorum_numbers: list[int],
        non_signer_operator_ids: list[int],
    ) -> OperatorStateRetrieverCheckSignaturesIndices: ...