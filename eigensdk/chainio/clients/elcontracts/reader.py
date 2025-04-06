import logging
from typing import Tuple, List, Any, Dict, Optional
from functools import wraps
from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from typeguard import typechecked
from web3.types import ChecksumAddress
from web3.exceptions import ContractLogicError, BadFunctionCallOutput


class ELReader:
    def __init__(
        self,
        allocation_manager: Contract,
        avs_directory: Contract,
        delegation_manager: Contract,
        permission_controller: Contract,
        reward_coordinator: Contract,
        strategy_manager: Contract,
        logger: logging.Logger,
        eth_client: Web3,
        strategy_abi: List[Dict[str, Any]],
        erc20_abi: List[Dict[str, Any]],
    ):
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permission_controller = permission_controller
        self.reward_coordinator = reward_coordinator
        self.strategy_manager = strategy_manager
        self.eth_client = eth_client
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi

        if allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        if avs_directory is None:
            raise ValueError("AvsDirectory contract not provided")

        if delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        if permission_controller is None:
            raise ValueError("PermissionController contract not provided")

        if reward_coordinator is None:
            raise ValueError("RewardCoordinator contract not provided")

        if strategy_manager is None:
            raise ValueError("StrategyManager contract not provided")

        if strategy_abi is None:
            raise ValueError("Strategy ABI not provided")

        if erc20_abi is None:
            raise ValueError("ERC20 ABI not provided")

    def get_allocatable_magnitude(self, operator_addr: Address, strategy_addr: Address) -> int:

        return self.allocation_manager.functions.getAllocatableMagnitude(
            operator_addr, strategy_addr
        ).call()

    def get_max_magnitudes(
        self, operator_addr: Address, strategy_addrs: List[Address]
    ) -> List[int]:

        return self.allocation_manager.functions.getMaxMagnitudes(
            operator_addr, strategy_addrs
        ).call()

    def get_allocation_info(
            self, operator_addr: Address, strategy_addr: Address
        ) -> List[Dict[str, Any]]:
        return [
            {
                "OperatorSetId": sid,
                "AvsAddress": avs,
                "CurrentMagnitude": mag,
                "PendingDiff": diff,
                "EffectBlock": block,
            }
            for (sid, avs), (mag, diff, block) in zip(
                *self.allocation_manager.functions.getStrategyAllocations(
                    operator_addr, strategy_addr
                ).call()
            )
        ]


    def get_operator_shares(
            self, operator_addr: Address, strategy_addresses: List[Address]
        ) -> List[int]:
        return self.delegation_manager.functions.getOperatorShares(
            operator_addr, strategy_addresses
        ).call()


    def get_operator_shares_single(
            self, operator_address: Address, strategy_addresses: List[Address]
        ) -> List[int]:
        return self.delegation_manager.functions.getOperatorShares(
            operator_address, strategy_addresses
        ).call()


    def get_operator_sets_for_operator(self, operator_addr: Address) -> List[Dict[str, Any]]:
        return [
            {"Id": s[0], "AvsAddress": s[1]}
            for s in self.allocation_manager.functions.getAllocatedSets(operator_addr).call()
        ]


    def get_allocation_delay(self, operator_addr: Address) -> int:
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(operator_addr).call()
        return delay if is_set else 0


    def get_registered_sets(self, operator_addr: Address) -> List[Dict[str, Any]]:
        return [
            {"Id": s[0], "Avs": s[1]}
            for s in self.allocation_manager.functions.getRegisteredSets(operator_addr).call()
        ]


    def calculate_operator_avs_registration_digestHash(
            self, operator_addr: Address, avs_addr: Address, salt: bytes, expiry: int
        ) -> bytes:
        return self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
            operator_addr, avs_addr, salt, expiry
        ).call()


    def is_operator_registered_with_avs(
            self, operator_address: Address, avs_address: Address
        ) -> bool:
        return self.avs_directory.functions.AvsOperatorStatus(avs_address, operator_address).call() == 1


    def is_operator_registered_with_operator_set(
            self, operator_addr: Address, operator_set: dict
        ) -> bool:
        return any(
            s[0] == operator_set.get("Id", 0) and s[1] == operator_set.get("Avs")
            for s in self.allocation_manager.functions.getRegisteredSets(operator_addr).call()
        )


    def is_operator_slashable(
            self, operator_address: Address, operator_set: Dict[str, Any]
        ) -> bool:
        return self.allocation_manager.functions.isOperatorSlashable(
            operator_address,
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"]),
        ).call()


    def get_allocated_stake(
            self,
            operator_set: Dict[str, Any],
            operator_addresses: List[Address],
            strategy_addresses: List[Address],
        ) -> List[List[int]]:
        key = (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"])
        stakes = self.allocation_manager.functions.getAllocatedStake(
            key, operator_addresses, strategy_addresses
        ).call()
        return stakes


    def get_operators_for_operator_set(self, operator_set: dict) -> List[Address]:
        return self.allocation_manager.functions.getMembers(
            (
                Web3.to_checksum_address(operator_set.get("Avs")),
                operator_set.get("Id", 0),
            )
        ).call()


    def get_num_operators_for_operator_set(self, operator_set: dict) -> int:
        return self.allocation_manager.functions.getMemberCount(
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"])
        ).call()


    def get_strategies_for_operator_set(self, operator_set: dict) -> List[Address]:
        if "Id" not in operator_set or "Avs" not in operator_set:
            raise ValueError("operator_set must contain 'Id' and 'Avs' keys.")
        if operator_set["Id"] == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")
        if not self.allocation_manager:
            raise ValueError("AllocationManager contract not provided")
        return self.allocation_manager.functions.getStrategiesInOperatorSet(
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"])
        ).call()


    def is_operator_registered(self, operator_address: Address) -> bool:
        return self.delegation_manager.functions.isOperator(operator_address).call()


    def get_staker_shares(self, staker_address: Address) -> Tuple[List[Address], List[int]]:
        return self.delegation_manager.functions.getDepositedShares(staker_address).call()


    def get_avs_registrar(self, avs_address: Address) -> Address:
        return self.allocation_manager.functions.getAVSRegistrar(avs_address).call()


    def get_delegated_operator(
            self, staker_address: Address, block_number: Optional[int] = None
        ) -> Address:
        return (
            self.delegation_manager.functions.delegatedTo(staker_address).call(
                block_identifier=block_number
            )
            if block_number
            else self.delegation_manager.functions.delegatedTo(staker_address).call()
        )


    def get_operator_details(self, operator: Dict[str, Any]) -> Dict[str, Any]:
        addr = Web3.to_checksum_address(operator["Address"])
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(addr).call()
        return dict(
            Address=addr,
            DelegationApproverAddress=self.delegation_manager.functions.delegationApproverSaltIsSpent(
                addr, b"\x00" * 32
            ).call(),
            AllocationDelay=delay if is_set else 0,
        )


    def get_operator_shares_in_strategy(
            self, operator_addr: Address, strategy_addr: Address
        ) -> int:
        return self.delegation_manager.functions.operatorShares(operator_addr, strategy_addr).call()


    def calculate_delegation_approval_digest_hash(
            self,
            staker: Address,
            operator: Address,
            delegation_approver: Address,
            approver_salt: bytes,
            expiry: int,
        ) -> bytes:
        return self.delegation_manager.functions.calculateDelegationApprovalDigestHash(
            staker, operator, delegation_approver, approver_salt, expiry
        ).call()


    def get_operators_shares(
            self, operator_addresses: List[Address], strategy_addresses: List[Address]
        ) -> List[List[int]]:
        return self.delegation_manager.functions.getOperatorsShares(
            operator_addresses, strategy_addresses
        ).call()


    def get_delegation_approver_salt_is_spent(
            self, delegation_approver: Address, approver_salt: bytes
        ) -> bool:
        return self.delegation_manager.functions.delegationApproverSaltIsSpent_


    def get_pending_withdrawal_status(self, withdrawal_root: bytes) -> bool:
        return self.delegation_manager.functions.pendingWithdrawals(withdrawal_root).call()


    def get_cumulative_withdrawals_queued(self, staker: Address) -> int:
        return self.delegation_manager.functions.cumulativeWithdrawalsQueued(staker).call()


    def can_call(
            self, account_address: Address, appointee_address: Address, target: Address, selector: bytes
        ) -> bool:
        return self.permission_controller.functions.canCall(
            account_address, appointee_address, target, selector
        ).call()


    def list_appointees(
            self, account_address: Address, target: Address, selector: bytes
        ) -> List[Address]:
        return self.permission_controller.functions.getAppointees(
            account_address, target, selector
        ).call()


    def list_appointee_permissions(
            self, account_address: Address, appointee_address: Address
        ) -> Tuple[List[Address], List[bytes]]:
        return self.permission_controller.functions.getAppointeePermissions(
            account_address, appointee_address
        ).call()


    def list_pending_admins(self, account_address: Address) -> List[Address]:
        return self.permission_controller.functions.getPendingAdmins(account_address).call()


    def list_admins(self, account_address: Address) -> List[Address]:
        return self.permission_controller.functions.getAdmins(account_address).call()


    def is_pending_admin(self, account_address: Address, pending_admin_address: Address) -> bool:
        return self.permission_controller.functions.isPendingAdmin(
            account_address, pending_admin_address
        ).call()


    def is_admin(self, account_address: Address, admin_address: Address) -> bool:
        return self.permission_controller.functions.isAdmin(account_address, admin_address).call()


    def get_distribution_roots_length(self) -> int:
        return self.reward_coordinator.functions.getDistributionRootsLength().call()

    def curr_rewards_calculation_end_timestamp(self) -> int:
        return self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()


    def get_current_claimable_distribution_root(self) -> Dict[str, Any]:
        return dict(
            zip(
                ["root", "startBlock", "endBlock", "totalClaimable"],
                self.reward_coordinator.functions.getCurrentClaimableDistributionRoot().call(),
            )
        )

    def get_root_index_from_hash(self, root_hash: bytes) -> int:
        return self.reward_coordinator.functions.getRootIndexFromHash(root_hash).call()


    def get_cumulative_claimed(self, earner: Address, token: Address) -> int:
        return self.reward_coordinator.functions.cumulativeClaimed(earner, token).call()


    def check_claim(self, claim: Dict[str, Any]) -> bool:
        return self.reward_coordinator.functions.checkClaim(
            (
                claim["root"],
                claim["index"],
                claim["account"],
                claim["amount"],
                claim["merkleProof"],
            )
        ).call()


    def get_operator_avs_split(self, operator: Address, avs: Address) -> int:
        return self.reward_coordinator.functions.getOperatorAVSSplit(operator, avs).call()


    def get_operator_pi_split(self, operator: Address) -> int:
        return self.reward_coordinator.functions.getOperatorPISplit(operator).call()

    def get_operator_set_split(self, operator: Address, operator_set: dict) -> int:
        return self.reward_coordinator.functions.getOperatorSetSplit(
            operator, (operator_set["avs"], operator_set["id"])
        ).call()


    def get_curr_rewards_calculation_end_timestamp(self) -> int:
        return self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()


    def get_rewards_updater(self) -> Address:
        return self.reward_coordinator.functions.rewardsUpdater().call()


    def get_default_operator_split_bips(self) -> int:
        return self.reward_coordinator.functions.defaultOperatorSplitBips().call()


    def get_claimer_for(self, earner: Address) -> Address:
        return self.reward_coordinator.functions.claimerFor(earner).call()


    def get_submission_nonce(self, avs: Address) -> int:
        return self.reward_coordinator.functions.submissionNonce(avs).call()


    def get_is_avs_rewards_submission_hash(self, avs: Address, hash: bytes) -> bool:
        return self.reward_coordinator.functions.isAVSRewardsSubmissionHash(avs, hash).call()


    def get_is_rewards_submission_for_all_hash(self, avs: Address, hash: bytes) -> bool:
        return self.reward_coordinator.functions.isRewardsSubmissionForAllHash(avs, hash).call()


    def get_is_rewards_for_all_submitter(self, submitter: Address) -> bool:
        return self.reward_coordinator.functions.isRewardsForAllSubmitter(submitter).call()


    def get_is_rewards_submission_for_all_earners_hash(self, avs: Address, hash: bytes) -> bool:
        return self.reward_coordinator.functions.isRewardsSubmissionForAllEarnersHash(avs, hash).call()


    def get_is_operator_directed_avs_rewards_submission_hash(
            self, avs: Address, hash: bytes
        ) -> bool:
        return self.reward_coordinator.functions.isOperatorDirectedAVSRewardsSubmissionHash(
            avs, hash
        ).call()


    def get_is_operator_directed_operator_set_rewards_submission_hash(
            self, avs: Address, hash: bytes
        ) -> bool:
        return self.reward_coordinator.functions.isOperatorDirectedOperatorSetRewardsSubmissionHash(
            avs, hash
        ).call()


    def get_strategy_and_underlying_token(
            self, strategy_addr: Address
        ) -> Tuple[Optional[Contract], Optional[str]]:
        sc = self.eth_client.eth.contract(address=strategy_addr, abi=self.strategy_abi)
        return sc, sc.functions.underlyingToken().call()


    def get_strategy_and_underlying_erc20_token(
            self, strategy_addr: Address
        ) -> Tuple[Optional[Contract], Optional[Contract], Optional[str]]:
        strategy_contract = self.eth_client.eth.contract(
            address=Web3.to_checksum_address(strategy_addr), abi=self.strategy_abi
        )
        token_addr = Web3.to_checksum_address(
            strategy_contract.functions.underlyingToken().call()
        )
        return (
            strategy_contract,
            self.eth_client.eth.contract(token_addr, abi=self.erc20_abi),
            token_addr,
        )

    def calculate_operator_avs_registration_digest_hash(
            self, operator: Address, avs: Address, salt: bytes, expiry: int
        ) -> bytes:
        return self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
            operator, avs, salt, expiry
        ).call()


    def get_encumbered_magnitude(self, operator_address: Address, strategy_address: Address) -> int:
        return self.allocation_manager.functions.getEncumberedMagnitude(
            operator_address, strategy_address
        ).call()


    def get_calculation_interval_seconds(self) -> Optional[int]:
        return self.reward_coordinator.functions.CALCULATION_INTERVAL_SECONDS().call()

    def get_max_rewards_duration(self) -> Optional[int]:
        return self.reward_coordinator.functions.MAX_REWARDS_DURATION().call()

    def get_max_retroactive_length(self) -> Optional[int]:
        return self.reward_coordinator.functions.MAX_RETROACTIVE_LENGTH().call()

    def get_max_future_length(self) -> Optional[int]:
        return self.reward_coordinator.functions.MAX_FUTURE_LENGTH().call()

    def get_genesis_rewards_timestamp(self) -> Optional[int]:
        return self.reward_coordinator.functions.GENESIS_REWARDS_TIMESTAMP().call()

    def get_activation_delay(self) -> Optional[int]:
        return self.reward_coordinator.functions.activationDelay().call()

    def get_deallocation_delay(self) -> Optional[int]:
        return self.allocation_manager.functions.DEALLOCATION_DELAY().call()

    def get_allocation_configuration_delay(self) -> Optional[int]:
        return self.allocation_manager.functions.ALLOCATION_CONFIGURATION_DELAY().call()

    def get_num_operator_sets_for_operator(self, operator_address: Address) -> int:
        return self.allocation_manager.functions.getAllocatedSets(operator_address).call()

    def get_slashable_shares(
            self, operator_address: Address, operator_set: Dict[str, Any], strategies: List[Address]
        ) -> Optional[Dict[str, int]]:
        shares = self.allocation_manager.functions.getMinimumSlashableStake(
            operator_set, [operator_address], strategies, self.eth_client.eth.block_number
        ).call()
        return {strategies[i]: shares[0][i] for i in range(len(strategies))}


    def get_slashable_shares_for_operator_sets_before(
            self, operator_sets: List[Dict[str, Any]], future_block: int
        ) -> Optional[List[Dict[str, Any]]]:
        result = []
        for op_set in operator_sets:
            op_set["Id"] = op_set.get("Id") or op_set.pop("id", None)
            strategies = self.get_strategies_for_operator_set(op_set)
            operators = self.get_operators_for_operator_set(op_set)
            stakes = self.allocation_manager.functions.getMinimumSlashableStake(
                {"Id": op_set["Id"], "Avs": op_set["Avs"]},
                operators,
                strategies,
                future_block,
            ).call()
            result.append(
                {
                    "OperatorSet": op_set,
                    "Strategies": strategies,
                    "Operators": operators,
                    "SlashableStakes": stakes,
                }
            )
        return result


    def get_slashable_shares_for_operator_sets(
            self, operator_sets: List[Dict[str, Any]]
        ) -> Optional[List[Dict[str, Any]]]:
        res = self.get_slashable_shares_for_operator_sets_before(
            operator_sets, self.eth_client.eth.block_number
        )
        return res if isinstance(res, list) else None
