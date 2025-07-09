import logging
from typing import Any

from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from web3.types import ChecksumAddress


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
        eth_http_client: Web3,
        strategy_abi: list[dict[str, Any]],
        erc20_abi: list[dict[str, Any]],
    ):
        """Initialize the ELReader with contract instances and configuration."""
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permission_controller = permission_controller
        self.reward_coordinator = reward_coordinator
        self.strategy_manager = strategy_manager
        self.eth_http_client = eth_http_client
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi

        if allocation_manager is None:
            self.logger.warning("AllocationManager contract not provided")

        if avs_directory is None:
            self.logger.warning("AvsDirectory contract not provided")

        if delegation_manager is None:
            self.logger.warning("DelegationManager contract not provided")

        if permission_controller is None:
            self.logger.warning("PermissionController contract not provided")

        if reward_coordinator is None:
            self.logger.warning("RewardCoordinator contract not provided")

        if strategy_manager is None:
            self.logger.warning("StrategyManager contract not provided")

        if strategy_abi is None:
            self.logger.warning("Strategy ABI not provided")

        if erc20_abi is None:
            self.logger.warning("ERC20 ABI not provided")

    def get_allocatable_magnitude(
        self,
        operator_addr: Address | ChecksumAddress | str | None,
        strategy_addr: Address | ChecksumAddress | str | None,
    ) -> int:
        """Returns the amount of magnitude on a strategy not currently allocated to any operator
        set, by an operator."""

        return self.allocation_manager.functions.getAllocatableMagnitude(
            operator_addr, strategy_addr
        ).call()

    def get_max_magnitudes(
        self,
        operator_addr: Address | ChecksumAddress | str | None,
        strategy_addrs: list[Address] | list[ChecksumAddress] | list[str],
    ) -> list[int]:
        """Returns the maximum magnitude an operator can allocate for the given strategies."""

        return self.allocation_manager.functions.getMaxMagnitudes(
            operator_addr, strategy_addrs
        ).call()

    def get_allocation_info(
        self,
        operator_addr: Address | ChecksumAddress | str | None,
        strategy_addr: Address | ChecksumAddress | str | None,
    ) -> list[dict[str, Any]]:
        """Returns the allocation info of a given operator and strategy."""
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
        self,
        operator_address: Address | ChecksumAddress | str | None,
        strategy_addresses: list[Address] | list[ChecksumAddress],
    ) -> list[int]:
        """Returns the shares an operator has delegated to them on a strategy."""
        return self.delegation_manager.functions.getOperatorShares(
            operator_address, strategy_addresses
        ).call()

    def get_operator_sets_for_operator(
        self, operator_addr: Address | str | None
    ) -> list[dict[str, Any]]:
        """Returns the list of operator sets the operator has current or pending
        allocations/deallocations in.

        This doesn't include M2 quorums.
        """
        return [
            {"Id": s[0], "AvsAddress": s[1]}
            for s in self.allocation_manager.functions.getAllocatedSets(operator_addr).call()
        ]

    def get_allocation_delay(self, operator_addr: Address | str | None) -> int:
        """Returns the time in blocks between an operator allocating slashable magnitude and the
        magnitude becoming slashable."""
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(operator_addr).call()
        return delay if is_set else 0

    def get_registered_sets(self, operator_addr: Address | str | None) -> list[dict[str, Any]]:
        """Returns a list of all operator sets the operator is registered for."""
        return [
            {"Id": s[0], "Avs": s[1]}
            for s in self.allocation_manager.functions.getRegisteredSets(operator_addr).call()
        ]

    def is_operator_registered_with_avs(
        self,
        operator_address: Address | str | None,
        avs_address: Address | str | None,
    ) -> bool:
        """Returns true if an operator is registered with a specific M2 quorum, querying
        AVSDirectory.

        Note: this method does not take into account operator sets.
        """
        return (
            self.avs_directory.functions.avsOperatorStatus(avs_address, operator_address).call()
            == 1
        )

    def is_operator_registered_with_operator_set(
        self, operator_addr: Address | str | None, operator_set: dict
    ) -> bool:
        """Returns true if an operator is registered with a specific operator set.

        Note: this method does not take into account M2 quorums.
        """
        return any(
            s[0] == operator_set.get("Id", 0) and s[1] == operator_set.get("Avs")
            for s in self.allocation_manager.functions.getRegisteredSets(operator_addr).call()
        )

    def is_operator_slashable(
        self, operator_address: Address | str | None, operator_set: dict[str, Any]
    ) -> bool:
        """Returns true if the received operator is slashable by the received operator set.

        Note: this method does not take into account M2 quorums.
        """
        return self.allocation_manager.functions.isOperatorSlashable(
            operator_address,
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"]),
        ).call()

    def get_allocated_stake(
        self,
        operator_set: dict[str, Any],
        operator_addresses: list[Address | ChecksumAddress],
        strategy_addresses: list[Address | ChecksumAddress],
    ) -> list[list[int]]:
        """Returns the current allocated stake, despite the operator's slashable status for the
        operatorSet.

        Note: this method does not take into account M2 quorums.
        """
        stakes = self.allocation_manager.functions.getAllocatedStake(
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"]),
            operator_addresses,
            strategy_addresses,
        ).call()
        return stakes

    def get_operators_for_operator_set(self, operator_set: dict) -> list:
        """Returns the list of operators in a specific operator set.

        Not supported for M2 AVSs.
        """

        if operator_set.get("id", 0) == 0:
            raise ValueError("Legacy AVSs not supported")

        if not self.allocation_manager:
            raise ValueError("AllocationManager contract not provided")

        operator_set_tuple = (
            Web3.to_checksum_address(operator_set["avs"]),
            operator_set.get("quorumNumber", 0),
        )

        operators = self.allocation_manager.functions.getMembers(operator_set_tuple).call()

        return operators

    def get_num_operators_for_operator_set(self, operator_set: dict) -> int:
        """Returns the number of operators in a specific operator set.

        Not supported for M2 AVSs.
        """
        return self.allocation_manager.functions.getMemberCount(
            (Web3.to_checksum_address(operator_set["Avs"]), operator_set["Id"])
        ).call()

    def get_strategies_for_operator_set(self, operator_set: dict) -> list[Address]:
        """Returns the list of strategies that an operator set takes into account.

        Not supported for M2 AVSs.
        """

        if operator_set.get("id", 0) == 0:
            raise ValueError("Legacy AVSs not supported")

        if not self.allocation_manager:
            raise ValueError("AllocationManager contract not provided")

        # Create the operator set tuple expected by the contract
        operator_set_tuple = (
            Web3.to_checksum_address(operator_set["avs"]),
            operator_set.get("quorumNumber", 0),
        )

        # Call the contract function
        strategies = self.allocation_manager.functions.getStrategiesInOperatorSet(
            operator_set_tuple
        ).call()

        return strategies

    def is_operator_registered(self, operator_address: Address | str | None) -> bool:
        """Returns true if the operator is registered to the EigenLayer protocol, false
        otherwise."""
        return self.delegation_manager.functions.isOperator(operator_address).call()

    def get_staker_shares(
        self, staker_address: Address | str | None
    ) -> tuple[list[Address], list[int]]:
        """Returns the amount of shares that a staker has in all of the strategies they have shares
        in."""
        return self.delegation_manager.functions.getDepositedShares(staker_address).call()

    def get_avs_registrar(self, avs_address: Address | str | None) -> Address:
        """Returns the AVSRegistrar of the avs received as parameter."""
        return self.allocation_manager.functions.getAVSRegistrar(avs_address).call()

    def get_delegated_operator(
        self, staker_address: Address | str | None, block_number: int | None = None
    ) -> Address:
        """Returns the operator that a staker has delegated to."""
        return (
            self.delegation_manager.functions.delegatedTo(staker_address).call(
                block_identifier=block_number
            )
            if block_number
            else self.delegation_manager.functions.delegatedTo(staker_address).call()
        )

    def get_operator_details(self, operator: dict[str, Any]) -> dict[str, Any]:
        """Returns detailed information on an operator."""
        addr = Web3.to_checksum_address(operator["Address"])
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(addr).call()
        return dict(
            Address=addr,
            DelegationApproverAddress=(
                self.delegation_manager.functions.delegationApproverSaltIsSpent(
                    addr, b"\x00" * 32
                ).call()
            ),
            AllocationDelay=delay if is_set else 0,
        )

    def get_operator_shares_in_strategy(
        self,
        operator_addr: Address | str | None,
        strategy_addr: Address | str | None,
    ) -> int:
        """Returns the shares an operator has in a given strategy."""
        return self.delegation_manager.functions.operatorShares(operator_addr, strategy_addr).call()

    def calculate_delegation_approval_digest_hash(
        self,
        staker: Address | str | None,
        operator: Address | str | None,
        delegation_approver: Address | str | None,
        approver_salt: bytes,
        expiry: int,
    ) -> bytes:
        """Returns the digest hash to be signed by the operator's delegation approver to be used
        when delegating to an operator."""
        return self.delegation_manager.functions.calculateDelegationApprovalDigestHash(
            staker, operator, delegation_approver, approver_salt, expiry
        ).call()

    def get_operators_shares(
        self,
        operator_addresses: list[Address | ChecksumAddress],
        strategy_addresses: list[Address | ChecksumAddress],
    ) -> list[list[int]]:
        """Returns the shares that a set of operators have delegated to them in a set of
        strategies."""
        return self.delegation_manager.functions.getOperatorsShares(
            operator_addresses, strategy_addresses
        ).call()

    def get_delegation_approver_salt_is_spent(
        self, delegation_approver: Address | str | None, approver_salt: bytes
    ) -> bool:
        """Returns whether delegationApprover has already used the given salt."""
        return self.delegation_manager.functions.delegationApproverSaltIsSpent(
            delegation_approver, approver_salt
        ).call()

    def get_pending_withdrawal_status(self, withdrawal_root: bytes) -> bool:
        """Returns whether a withdrawal is pending for a given withdrawalRoot."""
        return self.delegation_manager.functions.pendingWithdrawals(withdrawal_root).call()

    def get_cumulative_withdrawals_queued(self, staker: Address | str | None) -> int:
        """Returns the total number of withdrawals that have been queued for a given staker."""
        return self.delegation_manager.functions.cumulativeWithdrawalsQueued(staker).call()

    def can_call(
        self,
        account_address: Address | str | None,
        appointee_address: Address | str | None,
        target: Address | str | None,
        selector: bytes,
    ) -> bool:
        """Returns true if appointeeAddress has permission to call the function with the given
        selector on the target contract, on behalf of accountAddress, and false otherwise."""
        return self.permission_controller.functions.canCall(
            account_address, appointee_address, target, selector
        ).call()

    def list_appointees(
        self,
        account_address: Address | str | None,
        target: Address | str | None,
        selector: bytes,
    ) -> list[Address]:
        """Returns the list of appointees for a given account, target and function selector.

        Note that this doesn't include any of the appointed admins.
        """
        return self.permission_controller.functions.getAppointees(
            account_address, target, selector
        ).call()

    def list_appointee_permissions(
        self,
        account_address: Address | str | None,
        appointee_address: Address | str | None,
    ) -> tuple[list[Address], list[bytes]]:
        """Returns the list of permissions of an appointee for a given account."""
        return self.permission_controller.functions.getAppointeePermissions(
            account_address, appointee_address
        ).call()

    def list_pending_admins(self, account_address: Address | str | None) -> list[Address]:
        """Returns the pending admins of an account."""
        return self.permission_controller.functions.getPendingAdmins(account_address).call()

    def list_admins(self, account_address: Address | str | None) -> list[Address]:
        """Returns the admins of an account."""
        return self.permission_controller.functions.getAdmins(account_address).call()

    def is_pending_admin(
        self,
        account_address: Address | str | None,
        pending_admin_address: Address | str | None,
    ) -> bool:
        """Returns true if pendingAdminAddress is a pending admin for accountAddress, false
        otherwise."""
        return self.permission_controller.functions.isPendingAdmin(
            account_address, pending_admin_address
        ).call()

    def is_admin(
        self,
        account_address: Address | str | None,
        admin_address: Address | str | None,
    ) -> bool:
        """Returns true if adminAddress is an admin of accountAddress."""
        return self.permission_controller.functions.isAdmin(account_address, admin_address).call()

    def get_distribution_roots_length(self) -> int:
        """Returns the number of distribution roots published."""
        return self.reward_coordinator.functions.getDistributionRootsLength().call()

    def curr_rewards_calculation_end_timestamp(self) -> int:
        """Returns the timestamp until which rewards submissions have been calculated."""
        return self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()

    def get_current_claimable_distribution_root(self) -> dict[str, Any]:
        """Returns the latest root that can be claimed against."""
        return dict(
            zip(
                ["root", "startBlock", "endBlock", "totalClaimable"],
                self.reward_coordinator.functions.getCurrentClaimableDistributionRoot().call(),
            )
        )

    def get_root_index_from_hash(self, root_hash: bytes) -> int:
        """Returns the index of the latest root that can be claimed against."""
        return self.reward_coordinator.functions.getRootIndexFromHash(root_hash).call()

    def get_cumulative_claimed(
        self, earner: Address | str | None, token: Address | str | None
    ) -> int:
        """Returns the number of token tokens the earner has claimed."""
        return self.reward_coordinator.functions.cumulativeClaimed(earner, token).call()

    def check_claim(self, claim: dict[str, Any]) -> bool:
        """Returns true if the claim would currently pass the check in ChainWriter.ProcessClaims or
        return an error if invalid."""
        token_indices = claim.get("tokenIndices", [])
        token_tree_proofs = claim.get("tokenTreeProofs", [])
        token_leaves = claim.get("tokenLeaves", [])
        if not (len(token_indices) == len(token_tree_proofs) == len(token_leaves)):
            raise ValueError(
                "tokenIndices, tokenTreeProofs, and tokenLeaves must have the same length"
            )
        root_index = claim.get("rootIndex", 0)
        distribution_roots_length = self.get_distribution_roots_length()
        if distribution_roots_length == 0:
            raise ValueError("No distribution roots exist in the contract yet")
        if root_index < 0 or root_index >= distribution_roots_length:
            raise ValueError(
                f"""rootIndex {root_index} is out of bounds. Must be
                between 0 and {distribution_roots_length - 1}"""
            )
        earner_leaf = claim.get("earnerLeaf", {})
        if not earner_leaf.get("earner") or not Web3.is_address(earner_leaf.get("earner")):
            raise ValueError("Invalid earner address in earnerLeaf")
        if not earner_leaf.get("earnerTokenRoot") or len(earner_leaf.get("earnerTokenRoot")) != 32:
            raise ValueError("earnerTokenRoot must be 32 bytes")
        earner_leaf_tuple = (
            Web3.to_checksum_address(earner_leaf.get("earner")),
            earner_leaf.get("earnerTokenRoot"),
        )
        token_leaves_tuples = []
        for i, leaf in enumerate(token_leaves):
            if not leaf.get("token") or not Web3.is_address(leaf.get("token")):
                raise ValueError(f"Invalid token address in tokenLeaves[{i}]")
            if not isinstance(leaf.get("cumulativeEarnings"), int):
                raise ValueError(f"cumulativeEarnings must be an integer in tokenLeaves[{i}]")

            token_leaves_tuples.append(
                (
                    Web3.to_checksum_address(leaf.get("token")),
                    leaf.get("cumulativeEarnings", 0),
                )
            )
        claim_tuple = (
            root_index,
            claim.get("earnerIndex", 0),
            claim.get("earnerTreeProof", b""),
            earner_leaf_tuple,
            token_indices,
            token_tree_proofs,
            token_leaves_tuples,
        )
        return self.reward_coordinator.functions.checkClaim(claim_tuple).call()

    def get_operator_avs_split(
        self, operator: Address | str | None, avs: Address | str | None
    ) -> int:
        """Returns the split configured by the operator for the avs."""
        return self.reward_coordinator.functions.getOperatorAVSSplit(operator, avs).call()

    def get_operator_pi_split(self, operator: Address | str | None) -> int:
        """Returns the split configured by the operator for Programmatic Incentives."""
        return self.reward_coordinator.functions.getOperatorPISplit(operator).call()

    def get_operator_set_split(self, operator: Address | str | None, operator_set: dict) -> int:
        """Returns the split for an operator in an operator set."""
        return self.reward_coordinator.functions.getOperatorSetSplit(
            operator, (operator_set["Avs"], operator_set["Id"])
        ).call()

    def get_curr_rewards_calculation_end_timestamp(self) -> int:
        """Get timestamp for last submitted DistributionRoot."""
        return self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()

    def get_rewards_updater(self) -> Address | str | None:
        """Get the address of the entity that can update the contract with new merkle roots."""
        return self.reward_coordinator.functions.rewardsUpdater().call()

    def get_default_operator_split_bips(self) -> int:
        """Get the default split for all operators across all avss in bips."""
        return self.reward_coordinator.functions.defaultOperatorSplitBips().call()

    def get_claimer_for(self, earner: Address | str | None) -> Address:
        """Returns the claimer for the given earner."""
        return self.reward_coordinator.functions.claimerFor(earner).call()

    def get_submission_nonce(self, avs: Address | str | None) -> int:
        """Returns the submission nonce for an avs."""
        return self.reward_coordinator.functions.submissionNonce(avs).call()

    def get_is_avs_rewards_submission_hash(self, avs: Address | str | None, hash: bytes) -> bool:
        """Returns whether a hash is a valid rewards submission hash for a given avs."""
        return self.reward_coordinator.functions.isAVSRewardsSubmissionHash(avs, hash).call()

    def get_is_rewards_submission_for_all_hash(
        self, avs: Address | str | None, hash: bytes
    ) -> bool:
        """Returns whether a hash is a valid rewards submission for all hash for a given avs."""
        return self.reward_coordinator.functions.isRewardsSubmissionForAllHash(avs, hash).call()

    def get_is_rewards_for_all_submitter(self, submitter: Address | str | None) -> bool:
        """Returns whether a submitter is a valid rewards for all submitter."""
        return self.reward_coordinator.functions.isRewardsForAllSubmitter(submitter).call()

    def get_is_rewards_submission_for_all_earners_hash(
        self, avs: Address | str | None, hash: bytes
    ) -> bool:
        """Returns whether a hash is a valid rewards submission for all earners hash for a given
        avs."""
        return self.reward_coordinator.functions.isRewardsSubmissionForAllEarnersHash(
            avs, hash
        ).call()

    def get_is_operator_directed_avs_rewards_submission_hash(
        self, avs: Address | str | None, hash: bytes
    ) -> bool:
        """Returns whether a hash is a valid operator set performance rewards submission hash for a
        given avs."""
        return self.reward_coordinator.functions.isOperatorDirectedAVSRewardsSubmissionHash(
            avs, hash
        ).call()

    def get_is_operator_directed_operator_set_rewards_submission_hash(
        self, avs: Address | str | None, hash: bytes
    ) -> bool:
        """Returns whether a hash is a valid operator set performance rewards submission hash for a
        given avs."""
        return self.reward_coordinator.functions.isOperatorDirectedOperatorSetRewardsSubmissionHash(
            avs, hash
        ).call()

    def get_strategy_and_underlying_token(
        self, strategy_addr: Address | ChecksumAddress
    ) -> tuple[Contract, str | None]:
        """Returns the bindings of a given strategy and the address of its underlying token."""
        sc = self.eth_http_client.eth.contract(address=strategy_addr, abi=self.strategy_abi)
        return sc, sc.functions.underlyingToken().call()

    def get_strategy_and_underlying_erc20_token(
        self, strategy_addr: Address | ChecksumAddress
    ) -> tuple[Contract, Contract, str | None]:
        """Returns the bindings of a given strategy and the bindings and address of its underlying
        token."""
        strategy_contract = self.eth_http_client.eth.contract(
            address=Web3.to_checksum_address(strategy_addr), abi=self.strategy_abi
        )

        token_addr = Web3.to_checksum_address(strategy_contract.functions.underlyingToken().call())
        return (
            strategy_contract,
            self.eth_http_client.eth.contract(token_addr, abi=self.erc20_abi),
            token_addr,
        )

    def calculate_operator_avs_registration_digest_hash(
        self,
        operator: Address | str | None,
        avs: Address | str | None,
        salt: bytes,
        expiry: int,
    ) -> bytes:
        """Returns the digest hash to be signed by an operator to register with an AVS."""
        return self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
            operator, avs, salt, expiry
        ).call()

    def get_encumbered_magnitude(
        self,
        operator_address: Address | str | None,
        strategy_address: Address | str | None,
    ) -> int:
        """Returns the amount of magnitude an operator has allocated to operator sets for a given
        strategy."""
        return self.allocation_manager.functions.getEncumberedMagnitude(
            operator_address, strategy_address
        ).call()

    def get_calculation_interval_seconds(self) -> int:
        """Gets the interval in seconds at which the calculation for rewards distribution is
        done."""
        return self.reward_coordinator.functions.CALCULATION_INTERVAL_SECONDS().call()

    def get_max_rewards_duration(self) -> int:
        """Gets the maximum amount of time (seconds) that a rewards submission can span over."""
        return self.reward_coordinator.functions.MAX_REWARDS_DURATION().call()

    def get_max_retroactive_length(self) -> int:
        """Get the max amount of time (seconds) that a rewards submission can start in the past."""
        return self.reward_coordinator.functions.MAX_RETROACTIVE_LENGTH().call()

    def get_max_future_length(self) -> int:
        """Get the max amount of time (seconds) that a rewards submission can start in the
        future."""
        return self.reward_coordinator.functions.MAX_FUTURE_LENGTH().call()

    def get_genesis_rewards_timestamp(self) -> int:
        """Get absolute min timestamp (seconds) that a rewards submission can start at."""
        return self.reward_coordinator.functions.GENESIS_REWARDS_TIMESTAMP().call()

    def get_activation_delay(self) -> int:
        """Get delay in timestamp (seconds) before a posted root can be claimed against."""
        return self.reward_coordinator.functions.activationDelay().call()

    def get_deallocation_delay(self) -> int:
        """Returns the delay within which deallocations are slashable."""
        return self.allocation_manager.functions.DEALLOCATION_DELAY().call()

    def get_allocation_configuration_delay(self) -> int:
        """Returns the delay before allocation delay modifications take effect."""
        return self.allocation_manager.functions.ALLOCATION_CONFIGURATION_DELAY().call()

    def get_num_operator_sets_for_operator(self, operator_address: Address | str | None) -> int:
        """Returns the number of operator sets that an operator is part of.

        This doesn't include M2 quorums.
        """
        return self.allocation_manager.functions.getAllocatedSets(operator_address).call()

    def get_slashable_shares(
        self,
        operator_address: Address | ChecksumAddress | str | None,
        operator_set: dict[str, Any],
        strategies: list[Address | ChecksumAddress],
    ) -> dict[str, int] | None:
        """Returns a list of the number of shares slashable by the operator set for each of the
        given strategies."""
        if operator_address is None:
            return None
        return self.allocation_manager.functions.getMinimumSlashableStake(
            operator_set, [operator_address], strategies, self.eth_http_client.eth.block_number
        ).call()

    def get_slashable_shares_for_operator_sets_before(
        self, operator_sets: list[dict[str, Any]], future_block: int
    ) -> list[dict[str, Any]] | None:
        """Returns the strategies the operatorSets take into account, their operators, and the
        minimum amount of shares slashable by the operatorSets before a given timestamp.

        Timestamp must be in the future. Used to estimate future slashable stake. Not supported for
        M2 AVSs.
        """
        result = []
        for op_set in operator_sets:
            operators = self.get_operators_for_operator_set(op_set)
            strategies = self.get_strategies_for_operator_set(op_set)

            stakes = self.allocation_manager.functions.getMinimumSlashableStake(
                op_set,
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
        self, operator_sets: list[dict[str, Any]]
    ) -> list[dict[str, Any]] | None:
        """Returns the strategies the operatorSets take into account, their operators, and the
        minimum amount of shares that are slashable by the operatorSets.

        Not supported for M2 AVSs.
        """
        return self.get_slashable_shares_for_operator_sets_before(
            operator_sets, self.eth_http_client.eth.block_number
        )
