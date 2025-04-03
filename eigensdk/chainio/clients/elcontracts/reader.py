import logging
from typing import Tuple, List, Any, Dict, Optional

from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract
from typeguard import typechecked
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

    @typechecked
    def get_allocatable_magnitude(self, operator_addr: Address, strategy_addr: Address) -> int:

        return int(self.allocation_manager.functions.getAllocatableMagnitude(
            operator_addr, strategy_addr
        ).call())

    @typechecked
    def get_max_magnitudes(
        self, operator_addr: Address, strategy_addrs: List[Address]
    ) -> List[int]:

        return list(map(int, self.allocation_manager.functions.getMaxMagnitudes(
            operator_addr, strategy_addrs
        ).call()))

    @typechecked
    def get_allocation_info(
        self, operator_addr: Address, strategy_addr: Address
    ) -> List[Dict[str, Any]]:

        op_sets, allocation_info = self.allocation_manager.functions.getStrategyAllocations(
            operator_addr, strategy_addr
        ).call()

        if len(op_sets) != len(allocation_info):
            raise ValueError("Mismatched lengths of op_sets and allocation_info from contract.")

        results = []
        for i, op_set in enumerate(op_sets):
            op_set_id = str(op_set[0])
            avs_address = str(op_set[1])

            current_magnitude = int(allocation_info[i][0])
            pending_diff = int(allocation_info[i][1])
            effect_block = int(allocation_info[i][2])

            allocation_dict = {
                "OperatorSetId": op_set_id,
                "AvsAddress": avs_address,
                "CurrentMagnitude": current_magnitude,
                "PendingDiff": pending_diff,
                "EffectBlock": effect_block,
            }
            results.append(allocation_dict)

        return results


    @typechecked
    def get_operator_shares(
        self, operator_addr: Address, strategy_addresses: List[Address]
    ) -> List[int]:
        return list(map(int, self.delegation_manager.functions.getOperatorShares(
            operator_addr, strategy_addresses
        ).call()))


    @typechecked
    def get_operator_sets_for_operator(self, operator_addr: Address) -> List[Dict[str, Any]]:
        op_sets_raw = self.allocation_manager.functions.getAllocatedSets(operator_addr).call()

        operator_sets = []
        for op_set in op_sets_raw:
            parsed_set = {
                "Id": int(op_set[0]),
                "AvsAddress": str(op_set[1]),
            }
            operator_sets.append(parsed_set)

        return operator_sets


    @typechecked
    def get_allocation_delay(self, operator_addr: Address) -> int:
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(operator_addr).call()

        if not is_set:
            raise ValueError("allocation delay not set")

        return int(delay)


    @typechecked
    def get_registered_sets(self, operator_addr: Address) -> List[Dict[str, Any]]:
        raw_sets = self.allocation_manager.functions.getRegisteredSets(operator_addr).call()

        operator_sets = []
        for op_set in raw_sets:
            operator_set_dict = {
                "Id": int(op_set[0]),
                "Avs": str(op_set[1]),
            }
            operator_sets.append(operator_set_dict)

        return operator_sets


    @typechecked
    def calculate_operator_avs_registration_digestHash(
        self,
        operator_addr: Address,
        avs_addr: Address,
        salt: bytes,  # Must be 32 bytes in length
        expiry: int,
    ) -> bytes:
        digest_hash = self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
            operator_addr, avs_addr, salt, expiry
        ).call()

        return bytes(digest_hash)


    @typechecked
    def is_operator_registered_with_operator_set(
        self, operator_addr: Address, operator_set: dict
    ) -> bool:
        set_id = int(operator_set.get("Id", 0))
        avs_address = str(operator_set.get("Avs"))

        if set_id == 0:
            if self.avs_directory is None:
                raise ValueError("AVSDirectory contract not provided")

            status = int(self.avs_directory.functions.AvsOperatorStatus(
                avs_address, operator_addr
            ).call())
            return status == 1

        else:
            if self.allocation_manager is None:
                raise ValueError("AllocationManager contract not provided")

            registered_sets = self.allocation_manager.functions.getRegisteredSets(
                operator_addr
            ).call()

            for reg_set in registered_sets:
                reg_set_id = int(reg_set[0])
                reg_set_avs = str(reg_set[1])

                if reg_set_id == set_id and reg_set_avs == avs_address:
                    return True

            return False


    @typechecked
    def get_operators_for_operator_set(self, operator_set: dict) -> List[Address]:
        if not isinstance(operator_set, dict):
            raise TypeError("operator_set must be a dictionary with keys 'Id' and 'Avs'.")

        set_id = int(operator_set.get("Id", 0))
        avs_address = str(operator_set.get("Avs"))

        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        avs_address = Web3.to_checksum_address(avs_address)

        addresses = self.allocation_manager.functions.getMembers(
            (avs_address, set_id)
        ).call()

        return list(addresses)


    @typechecked
    def get_num_operators_for_operator_set(self, operator_set: dict) -> int:
        if "Id" not in operator_set or "Avs" not in operator_set:
            raise ValueError("operator_set must have 'Id' and 'Avs' keys.")

        set_id = int(operator_set["Id"])  # Convert ID to int for uint32
        avs_address = Web3.to_checksum_address(str(operator_set["Avs"]))  # Ensure string before checksumming

        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        member_count = self.allocation_manager.functions.getMemberCount(
            (avs_address, set_id)
        ).call()

        return int(member_count)


    @typechecked
    def get_strategies_for_operator_set(self, operator_set: dict) -> List[Address]:
        if "Id" not in operator_set or "Avs" not in operator_set:
            raise ValueError("operator_set must contain 'Id' and 'Avs' keys.")

        set_id = int(operator_set["Id"])
        avs_address = Web3.to_checksum_address(str(operator_set["Avs"]))

        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        strategies = self.allocation_manager.functions.getStrategiesInOperatorSet(
            (avs_address, set_id)
        ).call()

        return list(strategies)


    @typechecked
    def is_operator_registered(self, operator_address: Address) -> bool:
        is_registered = self.delegation_manager.functions.isOperator(operator_address).call()
        return bool(is_registered)


    @typechecked
    def get_staker_shares(self, staker_address: Address) -> Tuple[List[Address], List[int]]:
        strategy_addrs, share_amounts = self.delegation_manager.functions.getDepositedShares(
            staker_address
        ).call()

        return list(strategy_addrs), list(map(int, share_amounts))


    @typechecked
    def get_delegated_operator(
        self, staker_address: Address, block_number: Optional[int] = None
    ) -> Address:
        if block_number is not None:
            delegated_operator = self.delegation_manager.functions.delegatedTo(staker_address).call(
                block_identifier=block_number
            )
        else:
            delegated_operator = self.delegation_manager.functions.delegatedTo(
                staker_address
            ).call()

        # Remove '0x' prefix and convert hex string to bytes, then cast to Address
        return Address(bytes.fromhex(delegated_operator[2:]))


    @typechecked
    def get_operator_details(self, operator: Dict[str, Any]) -> Dict[str, Any]:
        operator_address = Web3.to_checksum_address(str(operator["Address"]))
        placeholder_salt = b"\x00" * 32  # 32 bytes of zeros

        try:
            delegation_manager_address = str(
                self.delegation_manager.functions.delegationApproverSaltIsSpent(
                    operator_address, placeholder_salt
                ).call()
            )
        except Exception as e:
            raise ValueError(f"Failed to fetch delegation approver salt: {e}") from e

        try:
            is_set, delay = self.allocation_manager.functions.getAllocationDelay(
                operator_address
            ).call()
        except Exception as e:
            raise ValueError(f"Failed to fetch allocation delay: {e}") from e

        allocation_delay = int(delay) if is_set else 0

        return {
            "Address": operator_address,
            "DelegationApproverAddress": delegation_manager_address,
            "AllocationDelay": allocation_delay,
        }


    @typechecked
    def get_operator_shares_in_strategy(
        self, operator_addr: Address, strategy_addr: Address
    ) -> int:
        shares = self.delegation_manager.functions.operatorShares(
            operator_addr, strategy_addr
        ).call()

        return int(shares)


    @typechecked
    def calculate_delegation_approval_digest_hash(
        self,
        staker: Address,
        operator: Address,
        delegation_approver: Address,
        approver_salt: bytes,
        expiry: int,
    ) -> bytes:
        digest_hash = self.delegation_manager.functions.calculateDelegationApprovalDigestHash(
            staker, operator, delegation_approver, approver_salt, expiry
        ).call()

        return bytes(digest_hash)


    @typechecked
    def get_operator_shares(
        self, operator_address: Address, strategy_addresses: List[Address]
    ) -> List[int]:
        shares_list = self.delegation_manager.functions.getOperatorShares(
            operator_address, strategy_addresses
        ).call()

        return list(map(int, shares_list))


    @typechecked
    def get_operators_shares(
        self, operator_addresses: List[Address], strategy_addresses: List[Address]
    ) -> List[List[int]]:
        shares_2d = self.delegation_manager.functions.getOperatorsShares(
            operator_addresses, strategy_addresses
        ).call()

        return [list(map(int, row)) for row in shares_2d]


    @typechecked
    def get_delegation_approver_salt_is_spent(
        self, delegation_approver: Address, approver_salt: bytes
    ) -> bool:
        salt_is_spent = self.delegation_manager.functions.delegationApproverSaltIsSpent(
            delegation_approver, approver_salt
        ).call()

        return bool(salt_is_spent)


    @typechecked
    def get_pending_withdrawal_status(self, withdrawal_root: bytes) -> bool:
        status = self.delegation_manager.functions.pendingWithdrawals(withdrawal_root).call()
        return bool(status)


    @typechecked
    def get_cumulative_withdrawals_queued(self, staker: Address) -> int:
        queued_amount = self.delegation_manager.functions.cumulativeWithdrawalsQueued(staker).call()
        return int(queued_amount)


    @typechecked
    def can_call(
        self,
        account_address: Address,
        appointee_address: Address,
        target: Address,
        selector: bytes,
    ) -> bool:
        try:
            can_call = self.permission_controller.functions.canCall(
                account_address, appointee_address, target, selector
            ).call()
        except Exception as e:
            raise ValueError(f"call to permission controller failed: {e}") from e

        return bool(can_call)


    @typechecked
    def list_appointees(
        self, account_address: Address, target: Address, selector: bytes
    ) -> List[Address]:
        try:
            appointees = self.permission_controller.functions.getAppointees(
                account_address, target, selector
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return list(appointees)


    @typechecked
    def list_appointee_permissions(
        self, account_address: Address, appointee_address: Address
    ) -> Tuple[List[Address], List[bytes]]:
        try:
            targets, selectors = self.permission_controller.functions.getAppointeePermissions(
                account_address, appointee_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return list(targets), list(selectors)


    @typechecked
    def list_pending_admins(self, account_address: Address) -> List[Address]:
        try:
            pending_admins = self.permission_controller.functions.getPendingAdmins(
                account_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return list(pending_admins)


    @typechecked
    def list_admins(self, account_address: Address) -> List[Address]:
        try:
            admins = self.permission_controller.functions.getAdmins(account_address).call()
            return [
                Address(bytes.fromhex(addr[2:])) for addr in admins  # Remove '0x' prefix
            ]
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e


    @typechecked
    def is_pending_admin(self, account_address: Address, pending_admin_address: Address) -> bool:
        try:
            is_pending_admin = self.permission_controller.functions.isPendingAdmin(
                account_address, pending_admin_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return bool(is_pending_admin)


    @typechecked
    def is_admin(self, account_address: Address, admin_address: Address) -> bool:
        try:
            is_admin = self.permission_controller.functions.isAdmin(
                account_address, admin_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return bool(is_admin)


    # -------------------------------------------------------
    # rewardcordinator
    # -------------------------------------------------------
    @typechecked
    def get_distribution_roots_length(self) -> int:
        length = self.reward_coordinator.functions.getDistributionRootsLength().call()
        return int(length)


    @typechecked
    def curr_rewards_calculation_end_timestamp(self) -> int:
        end_timestamp = (
            self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()
        )
        return int(end_timestamp)


    @typechecked
    def get_current_claimable_distribution_root(self) -> Dict[str, Any]:
        raw_data = self.reward_coordinator.functions.getCurrentClaimableDistributionRoot().call()

        distribution_root = {
            "root": str(raw_data[0]),
            "startBlock": int(raw_data[1]),
            "endBlock": int(raw_data[2]),
            "totalClaimable": int(raw_data[3]),
        }

        return distribution_root


    @typechecked
    def get_root_index_from_hash(self, root_hash: bytes) -> int:
        root_index = self.reward_coordinator.functions.getRootIndexFromHash(root_hash).call()
        return int(root_index)


    @typechecked
    def get_cumulative_claimed(self, earner: Address, token: Address) -> int:
        claimed_amount = self.reward_coordinator.functions.cumulativeClaimed(earner, token).call()
        return int(claimed_amount)


    @typechecked
    def check_claim(self, claim: Dict[str, Any]) -> bool:
        claim_tuple = (
            bytes(claim["root"]),          # bytes32
            int(claim["index"]),           # uint256
            str(claim["account"]),         # address
            int(claim["amount"]),          # uint256
            list(claim["merkleProof"]),    # bytes32[]
        )

        try:
            is_valid = self.reward_coordinator.functions.checkClaim(claim_tuple).call()
        except Exception:
            return False

        return bool(is_valid)


    @typechecked
    def get_operator_avs_split(self, operator: Address, avs: Address) -> int:
        avs_split = self.reward_coordinator.functions.getOperatorAVSSplit(operator, avs).call()
        return int(avs_split)


    @typechecked
    def get_operator_pi_split(self, operator: Address) -> int:
        pi_split = self.reward_coordinator.functions.getOperatorPISplit(operator).call()
        return int(pi_split)


    @typechecked
    def get_operator_set_split(self, operator: Address, operator_set: dict) -> int:
        operator_set_tuple = (
            str(operator_set["avs"]),
            int(operator_set["id"]),
        )  # FIXED ORDER

        op_set_split = self.reward_coordinator.functions.getOperatorSetSplit(
            operator, operator_set_tuple
        ).call()

        return int(op_set_split)


    @typechecked
    def get_rewards_updater(self) -> Address:
        rewards_updater = self.reward_coordinator.functions.rewardsUpdater().call()
        return Address(bytes.fromhex(rewards_updater[2:]))  # Remove '0x' prefix before converting



    @typechecked
    def get_curr_rewards_calculation_end_timestamp(self) -> int:
        end_timestamp = (
            self.reward_coordinator.functions.currRewardsCalculationEndTimestamp().call()
        )
        return int(end_timestamp)


    @typechecked
    def get_default_operator_split_bips(self) -> int:
        default_split_bips = self.reward_coordinator.functions.defaultOperatorSplitBips().call()
        return int(default_split_bips)


    @typechecked
    def get_claimer_for(self, earner: Address) -> Address:
        claimer_address = self.reward_coordinator.functions.claimerFor(earner).call()
        return Address(bytes.fromhex(claimer_address[2:]))  # Remove '0x' prefix before converting


    @typechecked
    def get_submission_nonce(self, avs: Address) -> int:
        submission_nonce = self.reward_coordinator.functions.submissionNonce(avs).call()
        return int(submission_nonce)


    @typechecked
    def get_is_avs_rewards_submission_hash(self, avs: Address, hash: bytes) -> bool:
        is_valid = self.reward_coordinator.functions.isAVSRewardsSubmissionHash(avs, hash).call()
        return bool(is_valid)


    @typechecked
    def get_is_rewards_submission_for_all_hash(self, avs: Address, hash: bytes) -> bool:
        is_valid = self.reward_coordinator.functions.isRewardsSubmissionForAllHash(avs, hash).call()
        return bool(is_valid)


    @typechecked
    def get_is_rewards_for_all_submitter(self, submitter: Address) -> bool:
        is_authorized = self.reward_coordinator.functions.isRewardsForAllSubmitter(submitter).call()
        return bool(is_authorized)


    @typechecked
    def get_is_rewards_submission_for_all_earners_hash(self, avs: Address, hash: bytes) -> bool:
        is_valid = self.reward_coordinator.functions.isRewardsSubmissionForAllEarnersHash(
            avs, hash
        ).call()
        return bool(is_valid)


    @typechecked
    def get_is_operator_directed_avs_rewards_submission_hash(
        self, avs: Address, hash: bytes
    ) -> bool:
        is_valid = self.reward_coordinator.functions.isOperatorDirectedAVSRewardsSubmissionHash(
            avs, hash
        ).call()
        return bool(is_valid)


    @typechecked
    def get_is_operator_directed_operator_set_rewards_submission_hash(
        self, avs: Address, hash: bytes
    ) -> bool:
        is_valid = (
            self.reward_coordinator.functions.isOperatorDirectedOperatorSetRewardsSubmissionHash(
                avs, hash
            ).call()
        )
        return bool(is_valid)


    @typechecked
    def get_strategy_and_underlying_token(
        self, strategy_addr: Address
    ) -> Tuple[Optional[Contract], Optional[str]]:
        strategy_contract = self.eth_client.eth.contract(
            address=strategy_addr, abi=self.strategy_abi
        )
        underlying_token_addr = strategy_contract.functions.underlyingToken().call()
        return strategy_contract, str(underlying_token_addr)



    @typechecked
    def get_strategy_and_underlying_erc20_token(
        self, strategy_addr: Address
    ) -> Tuple[Optional[Contract], Optional[Contract], Optional[str]]:
        strategy_checksum_addr = Web3.to_checksum_address(strategy_addr)

        strategy_contract = self.eth_client.eth.contract(
            address=strategy_checksum_addr, abi=self.strategy_abi
        )

        underlying_token_addr = strategy_contract.functions.underlyingToken().call()
        underlying_token_addr_str = str(underlying_token_addr)
        underlying_token_checksum = Web3.to_checksum_address(underlying_token_addr_str)

        underlying_token_contract = self.eth_client.eth.contract(
            address=underlying_token_checksum, abi=self.erc20_abi
        )

        return (
            strategy_contract,
            underlying_token_contract,
            underlying_token_addr_str,
        )


    @typechecked
    def calculate_operator_avs_registration_digest_hash(
        self,
        operator: Address,
        avs: Address,
        salt: bytes,
        expiry: int,
    ) -> bytes:
        digest_hash = self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
            operator, avs, salt, expiry
        ).call()
        return bytes(digest_hash)


    @typechecked
    def get_calculation_interval_seconds(self) -> Optional[int]:
        interval_seconds = self.reward_coordinator.functions.CALCULATION_INTERVAL_SECONDS().call()
        return int(interval_seconds)


    @typechecked
    def get_max_rewards_duration(self) -> Optional[int]:
        max_rewards_duration = self.reward_coordinator.functions.MAX_REWARDS_DURATION().call()
        return int(max_rewards_duration)


    @typechecked
    def get_max_retroactive_length(self) -> Optional[int]:
        max_retroactive_length = self.reward_coordinator.functions.MAX_RETROACTIVE_LENGTH().call()
        return int(max_retroactive_length)


    @typechecked
    def get_max_future_length(self) -> Optional[int]:
        max_future_length = self.reward_coordinator.functions.MAX_FUTURE_LENGTH().call()
        return int(max_future_length)


    @typechecked
    def get_genesis_rewards_timestamp(self) -> Optional[int]:
        genesis_rewards_timestamp = (
            self.reward_coordinator.functions.GENESIS_REWARDS_TIMESTAMP().call()
        )
        return int(genesis_rewards_timestamp)


    @typechecked
    def get_activation_delay(self) -> Optional[int]:
        activation_delay = self.reward_coordinator.functions.activationDelay().call()
        return int(activation_delay)


    @typechecked
    def get_deallocation_delay(self) -> Optional[int]:
        deallocation_delay = self.allocation_manager.functions.DEALLOCATION_DELAY().call()
        return int(deallocation_delay)


    @typechecked
    def get_allocation_configuration_delay(self) -> Optional[int]:
        allocation_configuration_delay = (
            self.allocation_manager.functions.ALLOCATION_CONFIGURATION_DELAY().call()
        )
        return int(allocation_configuration_delay)


    @typechecked
    def get_num_operator_sets_for_operator(
        self, operator_address: Address
    ) -> int:
        op_sets = self.allocation_manager.functions.getAllocatedSets(operator_address).call()
        return len(op_sets)


    @typechecked
    def get_slashable_shares(
        self,
        operator_address: Address,
        operator_set: Dict[str, Any],
        strategies: List[Address],
    ) -> Optional[Dict[str, int]]:
        avs_address = operator_set.get("avs") or operator_set.get("AVSAddress")
        if avs_address is None:
            return None

        current_block = self.eth_client.eth.block_number

        slashable_shares = self.allocation_manager.functions.getMinimumSlashableStake(
            operator_set, [operator_address], strategies, current_block
        ).call()

        if not slashable_shares or len(slashable_shares[0]) == 0:
            return None

        slashable_share_strategy_map = {
            str(strategies[i]): int(slashable_shares[0][i]) for i in range(len(strategies))
        }

        return slashable_share_strategy_map


    @typechecked
    def get_slashable_shares_for_operator_sets_before(
        self, operator_sets: List[Dict[str, Any]], future_block: int
    ) -> Optional[List[Dict[str, Any]]]:

        operator_set_stakes = []

        for operator_set in operator_sets:
            if "Id" not in operator_set and "id" in operator_set:
                operator_set["Id"] = operator_set.pop("id")

            if "Id" not in operator_set or "Avs" not in operator_set:
                raise ValueError(f"Invalid operator_set format: {operator_set}")

            set_id = int(operator_set["Id"])
            avs_address = str(operator_set["Avs"])

            if set_id == 0:
                raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

            operators = self.get_operators_for_operator_set(operator_set)
            if not operators:
                raise ValueError(f"Failed to get operators for OperatorSet: {operator_set}")

            strategies = self.get_strategies_for_operator_set(operator_set)
            if not strategies:
                raise ValueError(f"Failed to get strategies for OperatorSet: {operator_set}")

            try:
                slashable_shares = self.allocation_manager.functions.getMinimumSlashableStake(
                    {"Id": set_id, "Avs": avs_address},
                    operators,
                    strategies,
                    future_block,
                ).call()
            except Exception as e:
                raise ValueError(f"Failed to fetch slashable shares: {e}") from e

            operator_set_stakes.append(
                {
                    "OperatorSet": operator_set,
                    "Strategies": strategies,
                    "Operators": operators,
                    "SlashableStakes": slashable_shares,
                }
            )

        return operator_set_stakes

