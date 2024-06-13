from abc import ABC, abstractmethod
from dataclasses import dataclass
from eigensdk.crypto.bls.attestation import G1Point, G2Point, Signature
import eigensdk.crypto.bls.attestation as bls
from eigensdk.services.avsregistry.avsregistry import (
    AvsRegistryService,
    OperatorAvsState,
    QuorumAvsState,
    SignedTaskResponseDigest,
    CallOpts,
)
from eigensdk.utils import exeption_to_dict
import asyncio
import json


def is_json_serializable(obj):
    try:
        json.dumps(obj)
        return True
    except (TypeError, OverflowError) as e:
        # Handle specific exceptions related to JSON serialization issues
        # (e.g., TypeError for unsupported data types, OverflowError for large numbers)
        return False


@dataclass
class BlsAggregationServiceResponse:
    err: Exception = None  # if err is not None, the other fields are not valid
    task_index: int = None  # unique identifier of the task
    task_response: any = None  # the task response that was signed
    task_response_digest: any = None  # digest of the task response that was signed
    # The below 8 fields are the data needed to build the IBLSSignatureChecker.NonSignerStakesAndSignature struct
    # users of this service will need to build the struct themselves by converting the bls points
    # into the BN254.G1/G2Point structs that the IBLSSignatureChecker expects
    # given that those are different for each AVS service manager that individually inherits BLSSignatureChecker
    non_signers_pubkeys_g1: list[G1Point] = None
    quorum_apks_g1: list[G1Point] = None
    signers_apk_g2: G2Point = None
    signers_agg_sig_g1: Signature = None
    non_signer_quorum_bitmap_indices: list[int] = None
    quorum_apk_indices: list[int] = None
    total_stake_indices: list[int] = None
    non_signer_stake_indices: list[list[int]] = None

    def to_json(self, indent=None) -> str:
        if self.err is not None:
            return json.dumps({"err": exeption_to_dict(self.err)}, indent=indent)

        if not is_json_serializable(self.task_response):
            raise ValueError("Task response is not json serializable.")

        return json.dumps(
            {
                "err": str(self.err),
                "task_index": self.task_index,
                "task_response": self.task_response,
                "task_response_digest": self.task_response_digest.hex(),
                "non_signers_pubkeys_g1": [
                    {
                        "X": p.getX().getStr(16).decode("utf-8"),
                        "Y": p.getY().getStr(16).decode("utf-8"),
                    }
                    for p in self.non_signers_pubkeys_g1
                ],
                "quorum_apks_g1": [
                    {
                        "X": p.getX().getStr(16).decode("utf-8"),
                        "Y": p.getY().getStr(16).decode("utf-8"),
                    }
                    for p in self.quorum_apks_g1
                ],
                "signers_apk_g2": {
                    "X": [
                        self.signers_apk_g2.getX().get_a().getStr(16).decode("utf-8"),
                        self.signers_apk_g2.getX().get_b().getStr(16).decode("utf-8"),
                    ],
                    "Y": [
                        self.signers_apk_g2.getY().get_a().getStr(16).decode("utf-8"),
                        self.signers_apk_g2.getY().get_b().getStr(16).decode("utf-8"),
                    ],
                },
                "signers_agg_sig_g1": {
                    "X": self.signers_agg_sig_g1.getX().getStr(16).decode("utf-8"),
                    "Y": self.signers_agg_sig_g1.getY().getStr(16).decode("utf-8"),
                },
                "non_signer_quorum_bitmap_indices": self.non_signer_quorum_bitmap_indices,
                "quorum_apk_indices": self.quorum_apk_indices,
                "total_stake_indices": self.total_stake_indices,
                "non_signer_stake_indices": self.non_signer_stake_indices,
            },
            indent=indent,
        )


@dataclass
class AggregatedOperators:
    # aggregate g2 pubkey of all operatos who signed on this taskResponseDigest
    signers_apk_g2: G2Point
    # aggregate signature of all operators who signed on this taskResponseDigest
    signers_agg_sig_g1: Signature
    # aggregate stake of all operators who signed on this header for each quorum
    signers_total_stake_per_quorum: dict[int, int]
    # set of OperatorId of operators who signed on this header
    signers_operator_ids_set: dict[int, bool]


# BlsAggregationService is the interface provided to avs aggregator code for doing bls aggregation
# Currently its only implementation is the BlsAggregatorService, so see the comment there for more details
class BlsAggregationServiceInterface(ABC):
    # InitializeNewTask should be called whenever a new task is created. ProcessNewSignature will return an error
    # if the task it is trying to process has not been initialized yet.
    # quorumNumbers and quorumThresholdPercentages set the requirements for this task to be considered complete, which happens
    # when a particular TaskResponseDigest (received via the a.taskChans[taskIndex]) has been signed by signers whose stake
    # in each of the listed quorums adds up to at least quorumThresholdPercentages[i] of the total stake in that quorum
    @abstractmethod
    def initialize_new_task(
        task_index: int,
        task_created_block: int,
        quorum_numbers: list[int],
        quorum_threshold_percentages: list[int],
        time_to_expiry: int,
    ) -> Exception: ...

    # ProcessNewSignature processes a new signature over a taskResponseDigest for a particular taskIndex by a particular operator
    # It verifies that the signature is correct and returns an error if it is not, and then aggregates the signature and stake of
    # the operator with all other signatures for the same taskIndex and taskResponseDigest pair.
    # Note: This function currently only verifies signatures over the taskResponseDigest directly, so avs code needs to verify that the digest
    # passed to ProcessNewSignature is indeed the digest of a valid taskResponse (that is, BlsAggregationService does not verify semantic integrity of the taskResponses)
    @abstractmethod
    def process_new_signature(
        taskIndex: int,
        taskResponse: any,
        blsSignature: Signature,
        operatorId: int,
    ) -> Exception: ...

    # GetResponseChannel returns the single channel that meant to be used as the response channel
    # Any task that is completed (see the completion criterion in the comment above InitializeNewTask)
    # will be sent on this channel along with all the necessary information to call BLSSignatureChecker onchain
    @abstractmethod
    async def get_aggregated_response() -> BlsAggregationServiceResponse: ...


class BlsAggregationService(BlsAggregationServiceInterface):
    @dataclass
    class TaskListItem:
        task_created_block: int
        quorum_numbers: list[int]
        quorum_threshold_percentages: list[int]
        quorum_threshold_percentages_map: dict[int, int]
        operators_avs_state_dict: dict[int, OperatorAvsState]
        quorums_avs_state_dict: dict[int, QuorumAvsState]
        total_stake_per_quorum: dict[int, int]
        quorum_apks_g1: list[G1Point]
        aggregated_operators_dict: dict
        timeout: int
        future: asyncio.Future
        signatures: dict

    avs_registry_service: AvsRegistryService
    aggregated_responses: dict[int, TaskListItem]

    def __init__(
        self,
        avs_registry_service: AvsRegistryService,
        hash_function: any,
        # logger: any
    ) -> None:
        super().__init__()
        self.aggregated_responses = {}
        self.avs_registry_service = avs_registry_service
        # self.logger = logger
        self.hash_function = hash_function

    async def initialize_new_task(
        self,
        task_index: int,
        task_created_block: int,
        quorum_numbers: list[int],
        quorum_threshold_percentages: list[int],
        time_to_expiry: int,
    ) -> Exception:
        if task_index in self.aggregated_responses:
            raise ValueError("Task alredy initialized")

        quorum_threshold_percentages_map = {}
        for i, qn in enumerate(quorum_numbers):
            quorum_threshold_percentages_map[qn] = quorum_threshold_percentages[i]

        operators_avs_state_dict = (
            await self.avs_registry_service.get_operators_avs_state_at_block(
                quorum_numbers, task_created_block
            )
        )
        quorums_avs_state_dict = (
            await self.avs_registry_service.get_quorums_avs_state_at_block(
                quorum_numbers, task_created_block
            )
        )

        total_stake_per_quorum = {}
        for quorum_num, quorum_avs_state in quorums_avs_state_dict.items():
            total_stake_per_quorum[quorum_num] = quorum_avs_state.total_stake

        quorum_apks_g1 = []
        for i, qn in enumerate(quorum_numbers):
            quorum_apks_g1.append(quorums_avs_state_dict[qn].agg_pub_key_g1)

        self.aggregated_responses[task_index] = self.TaskListItem(
            task_created_block=task_created_block,
            quorum_numbers=quorum_numbers,
            quorum_threshold_percentages=quorum_threshold_percentages,
            quorum_threshold_percentages_map=quorum_threshold_percentages_map,
            operators_avs_state_dict=operators_avs_state_dict,
            quorums_avs_state_dict=quorums_avs_state_dict,
            total_stake_per_quorum=total_stake_per_quorum,
            quorum_apks_g1=quorum_apks_g1,
            aggregated_operators_dict={},
            timeout=time_to_expiry,
            future=asyncio.Future(),
            signatures={},
        )

    async def process_new_signature(
        self, task_index: int, task_response: str, bls_sign: Signature, operator_id: int
    ):
        if task_index not in self.aggregated_responses:
            raise ValueError("Task not initialized")
        if operator_id in self.aggregated_responses[task_index].signatures:
            raise ValueError("Operator signature has already been processed")

        cd = self.aggregated_responses[task_index]
        operators_avs_state_dict: dict[int, OperatorAvsState] = (
            cd.operators_avs_state_dict
        )

        err = self.__verify_signature(
            task_index=task_index,
            signed_task_response_digest=SignedTaskResponseDigest(
                task_response=task_response,
                bls_signature=bls_sign,
                operator_id=operator_id,
            ),
            operators_avs_state_dict=operators_avs_state_dict,
        )

        task_response_digest = self.hash_function(task_response)
        if task_response_digest not in cd.aggregated_operators_dict:
            digest_aggregated_operators: AggregatedOperators = AggregatedOperators(
                signers_apk_g2=bls.new_zero_g2_point()
                + operators_avs_state_dict[
                    operator_id
                ].operator_info.pub_keys.g2_pub_key,
                signers_agg_sig_g1=bls_sign,
                signers_operator_ids_set={operator_id: True},
                signers_total_stake_per_quorum=operators_avs_state_dict[
                    operator_id
                ].stake_per_quorum,
            )
        else:
            digest_aggregated_operators: AggregatedOperators = (
                cd.aggregated_operators_dict[task_response_digest]
            )

            digest_aggregated_operators.signers_agg_sig_g1 = (
                digest_aggregated_operators.signers_agg_sig_g1 + bls_sign
            )
            digest_aggregated_operators.signers_apk_g2 = (
                digest_aggregated_operators.signers_apk_g2
                + operators_avs_state_dict[
                    operator_id
                ].operator_info.pub_keys.g2_pub_key
            )
            digest_aggregated_operators.signers_operator_ids_set[operator_id] = True
            for quorum_num, stake_amount in operators_avs_state_dict[
                operator_id
            ].stake_per_quorum.items():
                if (
                    digest_aggregated_operators.signers_total_stake_per_quorum[
                        quorum_num
                    ]
                    is None
                ):
                    digest_aggregated_operators.signers_total_stake_per_quorum[
                        quorum_num
                    ] = 0
                digest_aggregated_operators.signers_total_stake_per_quorum[
                    quorum_num
                ] += stake_amount
        self.aggregated_responses[task_index].aggregated_operators_dict[
            task_response_digest
        ] = digest_aggregated_operators

        self.aggregated_responses[task_index].signatures[operator_id] = bls_sign

        if self.__stake_thresholds_met(
            signed_stake_per_quorum=digest_aggregated_operators.signers_total_stake_per_quorum,
            total_stake_per_quorum=cd.total_stake_per_quorum,
            quorum_threshold_percentages_map=cd.quorum_threshold_percentages_map,
        ):
            non_signers_operator_ids: list[int] = []
            for operator_id in operators_avs_state_dict:
                if (
                    operator_id
                    not in digest_aggregated_operators.signers_operator_ids_set
                ):
                    non_signers_operator_ids.append(operator_id)
            non_signers_operator_ids.sort()

            non_signers_g1_pub_keys: list[G1Point] = [
                operators_avs_state_dict[operator_id].operator_info.pub_keys.g1_pub_key
                for operator_id in non_signers_operator_ids
            ]

            indices, err = await self.avs_registry_service.get_check_signatures_indices(
                CallOpts(),
                cd.task_created_block,
                cd.quorum_numbers,
                non_signers_operator_ids,
            )
            if err is not None:
                raise err

            result = BlsAggregationServiceResponse(
                err=None,
                task_index=task_index,
                task_response=task_response,
                task_response_digest=task_response_digest,
                non_signers_pubkeys_g1=non_signers_g1_pub_keys,
                quorum_apks_g1=cd.quorum_apks_g1,
                signers_apk_g2=digest_aggregated_operators.signers_apk_g2,
                signers_agg_sig_g1=digest_aggregated_operators.signers_agg_sig_g1,
                non_signer_quorum_bitmap_indices=indices.non_signer_quorum_bitmap_indices,
                quorum_apk_indices=indices.quorum_apk_indices,
                total_stake_indices=indices.total_stake_indices,
                non_signer_stake_indices=indices.non_signer_stake_indices,
            )
            self.aggregated_responses[task_index].future.set_result(result)

    async def get_aggregated_response(self, task_index: int):
        # return await wait_for(self.aggregated_responses_c[task_index].future)
        try:
            result = await asyncio.wait_for(
                self.aggregated_responses[task_index].future,
                self.aggregated_responses[task_index].timeout,
            )
            return result, None
        except Exception as e:
            return BlsAggregationServiceResponse(
                err=asyncio.TimeoutError(f"task {task_index} expired")
            ), None

    def __stake_thresholds_met(
        self,
        signed_stake_per_quorum: dict[int, int],
        total_stake_per_quorum: dict[int, int],
        quorum_threshold_percentages_map: dict[int, int],
    ) -> bool:
        for (
            quorum_num,
            quorum_threshold_percentage,
        ) in quorum_threshold_percentages_map.items():
            signed_stake_by_quorum = signed_stake_per_quorum[quorum_num]
            if signed_stake_by_quorum is None:
                return False
            total_stake_by_quorum = total_stake_per_quorum[quorum_num]
            if total_stake_by_quorum is None:
                return False
            signed_stake = signed_stake_by_quorum * 100
            threshold_stake = total_stake_by_quorum * quorum_threshold_percentage
            if signed_stake < threshold_stake:
                return False
        return True

    def __verify_signature(
        self,
        task_index: int,
        signed_task_response_digest: SignedTaskResponseDigest,
        operators_avs_state_dict: dict[int, OperatorAvsState],
    ) -> Exception:
        operator_id = signed_task_response_digest.operator_id

        if operator_id not in operators_avs_state_dict:
            return ValueError(f"Operator {operator_id} is not part of task quorum")

        task_response_digest = self.hash_function(
            signed_task_response_digest.task_response
        )

        operator_g2_pub_key = operators_avs_state_dict[
            operator_id
        ].operator_info.pub_keys.g2_pub_key
        if not operator_g2_pub_key:
            return ValueError(
                f"TaskId: {task_index} operator G2 PubKey not fount for operator {operator_id}"
            )

        signature = signed_task_response_digest.bls_signature
        verified = signature.verify(operator_g2_pub_key, task_response_digest)
        if not verified:
            return ValueError("Incorrect signature error")

        return None
