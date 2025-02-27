import logging
from typing import Tuple, List, Any, Dict, Optional

from eth_typing import Address
from web3 import Web3
from web3.contract.contract import Contract

from eigensdk._types import Operator
from eigensdk.contracts import ABIs


class ELReader:
    def __init__(
        self,
        allocation_manager: Contract,
        avs_directory: Contract,
        delegation_manager: Contract,
        permissioncontrol: Contract,
        reward_cordinator: Contract,
        strategy_manager: Contract,
        logger: logging.Logger,
        eth_http_client: Web3,
        strategy_abi: List[Dict[str, Any]],
        erc20_abi: List[Dict[str, Any]],
    ):
        self.allocation_manager = allocation_manager
        self.avs_directory = avs_directory
        self.delegation_manager = delegation_manager
        self.permissioncontrol = permissioncontrol
        self.reward_cordinator = reward_cordinator
        self.strategy_manager = strategy_manager
        self.eth_http_client = eth_http_client
        self.logger = logger
        self.strategy_abi = strategy_abi
        self.erc20_abi = erc20_abi

    # -------------------------------------------------------
    # AllocationManager
    # -------------------------------------------------------
    def get_allocatable_magnitude(
        self, operator_addr: Address, strategy_addr: Address
    ) -> int:
        # Check if we have a valid AllocationManager contract instance
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # Perform the read-only call to the Solidity function `getAllocatableMagnitude(operator, strategy)`
        allocatable_magnitude: int = (
            self.allocation_manager.functions.getAllocatableMagnitude(
                operator_addr, strategy_addr
            ).call()
        )

        return allocatable_magnitude

    def get_encumbered_magnitude(
        self, operator_addr: Address, strategy_addr: Address
    ) -> int:

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        encumbered_magnitude: int = (
            self.allocation_manager.functions.encumberedMagnitude(
                operator_addr, strategy_addr
            ).call()
        )

        return encumbered_magnitude

    def get_max_magnitudes(
        self, operator_addr: Address, strategy_addrs: List[Address]
    ) -> List[int]:
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # In the Go version, the Solidity function name is `GetMaxMagnitudes0`.
        # Adapt it exactly as your contract's ABI specifies:
        max_magnitudes: List[int] = self.allocation_manager.functions.getMaxMagnitudes(
            operator_addr, strategy_addrs
        ).call()

        return max_magnitudes

    def get_allocation_info(
        self, operator_addr: Address, strategy_addr: Address
    ) -> List[Dict[str, Any]]:

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # Call the contract function that returns (opSets, allocationInfo)
        # The function name below must match your contract's ABI exactly.
        # For example: .GetStrategyAllocations(operator_addr, strategy_addr).call()
        # Adjust as needed if the actual name differs.
        op_sets, allocation_info = (
            self.allocation_manager.functions.getStrategyAllocations(
                operator_addr, strategy_addr
            ).call()
        )

        # op_sets and allocation_info should be lists/tuples of the same length
        if len(op_sets) != len(allocation_info):
            raise ValueError(
                "Mismatched lengths of op_sets and allocation_info from contract."
            )

        results = []
        for i, op_set in enumerate(op_sets):
            # 'op_set' might be a tuple/struct with fields like:
            #    op_set.Id and op_set.Avs in Go
            # In Python, that's typically returned as a tuple (Id, Avs, ...)
            # Similarly, 'allocation_info[i]' might have (CurrentMagnitude, PendingDiff, EffectBlock).
            # Adjust indices accordingly based on your ABI or actual returned data structure.

            # Example assumption:
            #   op_set = (Id, AvsAddress)
            #   allocation_info[i] = (currentMagnitude, pendingDiff, effectBlock)
            op_set_id = op_set[0]
            avs_address = op_set[1]

            current_magnitude = allocation_info[i][0]
            pending_diff = allocation_info[i][1]
            effect_block = allocation_info[i][2]

            # Build a dictionary that matches the Go 'AllocationInfo' structure
            allocation_dict = {
                "OperatorSetId": op_set_id,
                "AvsAddress": avs_address,
                "CurrentMagnitude": current_magnitude,
                "PendingDiff": pending_diff,
                "EffectBlock": effect_block,
            }
            results.append(allocation_dict)

        return results

    def get_operator_shares(
        self, operator_addr: Address, strategy_addresses: List[Address]
    ) -> List[int]:
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # The contract function name in Solidity is presumably `GetOperatorShares`.
        # Adjust if your ABI uses a different name.
        shares_list = self.delegation_manager.functions.getOperatorShares(
            operator_addr, strategy_addresses
        ).call()

        # shares_list is a list of integers in Python.
        return shares_list

    def get_operator_sets_for_operator(
        self, operator_addr: Address
    ) -> List[Dict[str, Any]]:
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # Call the contract function.
        # (Adjust the name `GetAllocatedSets` if your ABI differs.)
        op_sets_raw = self.allocation_manager.functions.getAllocatedSets(
            operator_addr
        ).call()

        # op_sets_raw is presumably a list of "OperatorSet" structs.
        # Each item might look like (id, avsAddress, someOtherField, ...)
        # We'll parse each tuple into a dictionary for easier usage in Python.

        operator_sets = []
        for op_set in op_sets_raw:
            # Example assumption of fields: (id, avsAddress, metadata, etc.)
            # Adjust indexes/naming as needed for your ABI:
            parsed_set = {
                "Id": op_set[0],
                "AvsAddress": op_set[1],
                # Uncomment/adjust if there are more fields in the struct:
                # "SomeField": op_set[2],
                # "AnotherField": op_set[3],
            }
            operator_sets.append(parsed_set)

        return operator_sets

    def get_allocation_delay(self, operator_addr: Address) -> int:
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # Solidity function presumably returns a tuple: (bool isSet, uint32 delay)
        is_set, delay = self.allocation_manager.functions.getAllocationDelay(
            operator_addr
        ).call()

        if not is_set:
            raise ValueError("allocation delay not set")

        return delay

    def get_registered_sets(self, operator_addr: Address) -> List[Dict[str, Any]]:

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # Call the contract function to get the registered sets.
        # The return value will depend on your ABI; typically it might be a list of tuples.
        raw_sets = self.allocation_manager.functions.getRegisteredSets(
            operator_addr
        ).call()

        # Convert each returned tuple to a dictionary. Adjust the field names and indices as needed.
        operator_sets = []
        for op_set in raw_sets:
            # Example: assume each op_set is a tuple (id, avs, ...)
            operator_set_dict = {
                "Id": op_set[0],
                "Avs": op_set[1],
                # Add additional fields as required.
            }
            operator_sets.append(operator_set_dict)

        return operator_sets

    # -------------------------------------------------------
    # avsdirectory
    # -------------------------------------------------------
    def calculate_operator_avs_registration_digestHash(
        self,
        operator_addr: Address,
        avs_addr: Address,
        salt: bytes,  # Must be 32 bytes in length
        expiry: int,
    ) -> bytes:
        if self.avs_directory is None:
            raise ValueError("AVSDirectory contract not provided")

        # Call the contract function.
        # Adjust the name if your contract's ABI differs.
        digest_hash = (
            self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
                operator_addr, avs_addr, salt, expiry
            ).call()
        )

        # Typically returns 32 bytes. Might be `HexBytes` in web3.py, which is fine to treat as bytes.
        # If you prefer to return a hex string, you can do: `return digest_hash.hex()`
        return digest_hash

    # operator_set = {
    #     "Id": some_uint64,
    #     "Avs": some_address
    # }

    def is_operator_registered_with_operator_set(
        self, operator_addr: Address, operator_set: dict
    ) -> bool:

        # operator_set is expected to have keys: "Id" and "Avs"
        set_id = operator_set.get("Id", 0)
        avs_address = operator_set.get("Avs")

        # If Id == 0 => M2 AVS
        if set_id == 0:
            # We need the AVSDirectory contract
            if self.avs_directory is None:
                raise ValueError("AVSDirectory contract not provided")

            # Call avsDirectory.AvsOperatorStatus(avs, operator)
            # The Go code returns 'status', then checks 'status == 1'
            status = self.avs_directory.functions.AvsOperatorStatus(
                avs_address, operator_addr
            ).call()
            # In Go, 'status == 1' means True, otherwise False
            return status == 1

        else:
            # We need the AllocationManager contract
            if self.allocation_manager is None:
                raise ValueError("AllocationManager contract not provided")

            # Get all registered sets for this operator
            registered_sets = self.allocation_manager.functions.getRegisteredSets(
                operator_addr
            ).call()

            # Each item in registered_sets is presumably a tuple or struct with (Id, Avs, ...).
            # We check if there's a match with our operator_set.
            for reg_set in registered_sets:
                # Example assumption: reg_set = (regSetId, regSetAvs, ...)
                reg_set_id = reg_set[0]
                reg_set_avs = reg_set[1]

                if reg_set_id == set_id and reg_set_avs == avs_address:
                    return True

            return False

    def get_operators_for_operator_set(self, operator_set: dict) -> List[Address]:
        """Retrieve operators for a given operator set."""
        # Ensure operator_set is a dictionary
        if not isinstance(operator_set, dict):
            raise TypeError(
                "operator_set must be a dictionary with keys 'Id' and 'Avs'."
            )
        # Extract values
        set_id = operator_set.get("Id", 0)
        avs_address = operator_set.get("Avs")
        # Check for legacy AVS
        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")
        # Ensure AllocationManager contract is set
        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")
        # Convert address to checksum format
        avs_address = Web3.to_checksum_address(avs_address)
        # Call contract function with correct tuple format
        addresses = self.allocation_manager.functions.getMembers(
            (avs_address, set_id)  # Address first, then uint32
        ).call()
        return addresses

    def get_num_operators_for_operator_set(self, operator_set: dict) -> int:
        """Get the number of operators in an operator set."""

        if "Id" not in operator_set or "Avs" not in operator_set:
            raise ValueError("operator_set must have 'Id' and 'Avs' keys.")

        set_id = int(operator_set["Id"])  # Convert ID to int for uint32
        avs_address = Web3.to_checksum_address(operator_set["Avs"])  # Convert address

        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # ✅ Correctly passing as a tuple `(address, uint32)`
        member_count = self.allocation_manager.functions.getMemberCount(
            (avs_address, set_id)  # ✅ Pass as (address, uint32)
        ).call()

        return member_count

    def get_strategies_for_operator_set(self, operator_set: dict) -> List[Address]:
        """Fetch strategies associated with an operator set."""

        # Validate operator set format
        if "Id" not in operator_set or "Avs" not in operator_set:
            raise ValueError("operator_set must contain 'Id' and 'Avs' keys.")

        set_id = int(operator_set["Id"])  # Convert ID to int for uint32
        avs_address = Web3.to_checksum_address(
            operator_set["Avs"]
        )  # Convert to checksum address

        if set_id == 0:
            raise ValueError("Legacy AVSs not supported (operatorSet.Id == 0)")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        # ✅ Correcting the tuple structure (avs_address first, then set_id)
        strategies = self.allocation_manager.functions.getStrategiesInOperatorSet(
            (avs_address, set_id)  # ✅ Correct order: (address, uint32)
        ).call()

        return strategies

    # -------------------------------------------------------
    # delegationmanager
    # -------------------------------------------------------
    def is_operator_registered(self, operator_address: str) -> bool:

        # Check if the contract instance is available
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # Convert the address string to whatever format web3.py expects
        # (If it's already a proper '0x'-prefixed string, that's usually sufficient.)
        is_registered = self.delegation_manager.functions.isOperator(
            operator_address
        ).call()

        return is_registered

    def get_staker_shares(
        self, staker_address: Address
    ) -> Tuple[List[Address], List[int]]:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # Call the contract function.
        # Adjust the name if your ABI differs (e.g. 'getDepositedShares' vs. 'GetDepositedShares').
        strategy_addrs, share_amounts = (
            self.delegation_manager.functions.getDepositedShares(staker_address).call()
        )

        # 'strategy_addrs' will be a list of addresses (e.g. ["0x1234...", "0xABCD..."])
        # 'share_amounts' will be a list of big integers, which Python can handle as int.

        return strategy_addrs, share_amounts

    def get_delegated_operator(
        self, staker_address: Address, block_number: Optional[int] = None
    ) -> Address:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # If you want to specify a block number, use call(..., block_identifier=block_number).
        # Otherwise, omit it to use the latest block.
        if block_number is not None:
            delegated_operator = self.delegation_manager.functions.delegatedTo(
                staker_address
            ).call(block_identifier=block_number)
        else:
            delegated_operator = self.delegation_manager.functions.delegatedTo(
                staker_address
            ).call()

        return delegated_operator

    def get_operator_details(self, operator: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch details of an operator."""

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        if self.allocation_manager is None:
            raise ValueError("AllocationManager contract not provided")

        operator_address = Web3.to_checksum_address(
            operator["Address"]
        )  # Convert to checksum format

        # ✅ Provide a placeholder bytes32 value (adjust as needed)
        placeholder_salt = b"\x00" * 32  # 32 bytes of zeros

        try:
            # ✅ Pass both required arguments (address, bytes32)
            delegation_manager_address = (
                self.delegation_manager.functions.delegationApproverSaltIsSpent(
                    operator_address, placeholder_salt
                ).call()
            )
        except Exception as e:
            raise ValueError(f"Failed to fetch delegation approver salt: {e}") from e

        # ✅ Fetch allocation delay
        try:
            is_set, delay = self.allocation_manager.functions.getAllocationDelay(
                operator_address
            ).call()
        except Exception as e:
            raise ValueError(f"Failed to fetch allocation delay: {e}") from e

        # Default to 0 if allocation delay isn't set
        allocation_delay = delay if is_set else 0

        # ✅ Return structured operator details
        return {
            "Address": operator_address,
            "DelegationApproverAddress": delegation_manager_address,
            "AllocationDelay": allocation_delay,
        }

    def get_operator_shares_in_strategy(
        self, operator_addr: Address, strategy_addr: Address
    ) -> int:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # In Go: r.delegationManager.OperatorShares(&bind.CallOpts{...}, operatorAddr, strategyAddr)
        # In Python/web3.py:
        shares = self.delegation_manager.functions.operatorShares(
            operator_addr, strategy_addr
        ).call()

        # web3.py will return the integer value directly (no overflow issues).
        return shares

    def calculate_delegation_approval_digest_hash(
        self,
        staker: Address,
        operator: Address,
        delegation_approver: Address,
        approver_salt: bytes,  # must be exactly 32 bytes in length
        expiry: int,  # Go uses *big.Int, Python int is fine
    ) -> bytes:
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        digest_hash = (
            self.delegation_manager.functions.calculateDelegationApprovalDigestHash(
                staker, operator, delegation_approver, approver_salt, expiry
            ).call()
        )

        return digest_hash

    def get_operator_shares(
        self, operator_address: Address, strategy_addresses: List[Address]
    ) -> List[int]:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # In Go: r.delegationManager.GetOperatorShares(&bind.CallOpts{...}, operatorAddress, strategyAddresses)
        # In Python/web3.py:
        shares_list = self.delegation_manager.functions.getOperatorShares(
            operator_address, strategy_addresses
        ).call()

        # shares_list is typically a list of big integers from Solidity (uint256),
        # but Python automatically converts them to int.
        return shares_list

    def get_operators_shares(
        self, operator_addresses: List[Address], strategy_addresses: List[Address]
    ) -> List[List[int]]:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # In Go: r.delegationManager.GetOperatorsShares(&bind.CallOpts{Context: ctx}, operatorAddresses, strategyAddresses)
        # In Python/web3.py:
        shares_2d = self.delegation_manager.functions.getOperatorsShares(
            operator_addresses, strategy_addresses
        ).call()

        # shares_2d should be a list of lists (2D array), each element is a "big integer" in Solidity
        # which Python automatically treats as int.
        return shares_2d

    def get_delegation_approver_salt_is_spent(
        self, delegation_approver: Address, approver_salt: bytes
    ) -> bool:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # The Go code calls r.delegationManager.DelegationApproverSaltIsSpent(...)
        salt_is_spent = self.delegation_manager.functions.delegationApproverSaltIsSpent(
            delegation_approver, approver_salt
        ).call()

        return salt_is_spent

    def get_pending_withdrawal_status(self, withdrawal_root: bytes) -> bool:

        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # Calls 'PendingWithdrawals(withdrawal_root)' on the DelegationManager contract
        status = self.delegation_manager.functions.pendingWithdrawals(
            withdrawal_root
        ).call()

        return status

    def get_cumulative_withdrawals_queued(self, staker: Address) -> int:
        if self.delegation_manager is None:
            raise ValueError("DelegationManager contract not provided")

        # In Go, this calls: r.delegationManager.CumulativeWithdrawalsQueued(...)
        queued_amount = self.delegation_manager.functions.cumulativeWithdrawalsQueued(
            staker
        ).call()

        # This is typically returned as a big integer by Solidity,
        # but Python automatically converts it to a standard int.
        return queued_amount

    # -------------------------------------------------------
    # permissioncontrol
    # -------------------------------------------------------
    def can_call(
        self,
        account_address: Address,
        appointee_address: Address,
        target: Address,
        selector: bytes,
    ) -> bool:
        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            can_call = self.permissioncontrol.functions.canCall(
                account_address, appointee_address, target, selector
            ).call()
        except Exception as e:
            # In Go code, it wraps the error with "utils.WrapError(...)".
            # In Python, we can raise a new exception or re-raise with context.
            raise ValueError(f"call to permission controller failed: {e}") from e

        return can_call

    def list_appointees(
        self, account_address: Address, target: Address, selector: bytes
    ) -> List[Address]:
        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            appointees = self.permissioncontrol.functions.getAppointees(
                account_address, target, selector
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return appointees

    def list_appointee_permissions(
        self, account_address: Address, appointee_address: Address
    ) -> Tuple[List[Address], List[bytes]]:

        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            # The contract function presumably returns (targets, selectors),
            # where targets is address[], selectors is bytes4[] in Solidity.
            targets, selectors = (
                self.permissioncontrol.functions.getAppointeePermissions(
                    account_address, appointee_address
                ).call()
            )
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        # 'targets' should be a list of addresses (e.g. ["0x...", "0x..."]).
        # 'selectors' should be a list of 4-byte values, which web3.py typically provides as bytes (e.g., b"\x12\x34\x56\x78").
        return targets, selectors

    def list_pending_admins(self, account_address: Address) -> List[Address]:

        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            pending_admins = self.permissioncontrol.functions.getPendingAdmins(
                account_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        # 'pending_admins' should be a list of addresses, e.g. ["0x...", "0x..."].
        return pending_admins

    def list_admins(self, account_address: Address) -> List[Address]:

        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            admins = self.permissioncontrol.functions.getAdmins(account_address).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return admins

    def is_pending_admin(
        self, account_address: Address, pending_admin_address: Address
    ) -> bool:
        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            is_pending_admin = self.permissioncontrol.functions.isPendingAdmin(
                account_address, pending_admin_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return is_pending_admin

    def is_admin(self, account_address: Address, admin_address: Address) -> bool:
        if self.permissioncontrol is None:
            raise ValueError("PermissionController contract not provided")

        try:
            is_admin = self.permissioncontrol.functions.isAdmin(
                account_address, admin_address
            ).call()
        except Exception as e:
            raise ValueError(f"Call to permission controller failed: {e}") from e

        return is_admin

    # -------------------------------------------------------
    # rewardcordinator
    # -------------------------------------------------------
    def get_distribution_roots_length(self) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        length = self.reward_cordinator.functions.getDistributionRootsLength().call()
        return length

    def curr_rewards_calculation_end_timestamp(self) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        # In Go: r.rewardsCoordinator.CurrRewardsCalculationEndTimestamp(...)
        # In Python (web3.py):
        end_timestamp = (
            self.reward_cordinator.functions.currRewardsCalculationEndTimestamp().call()
        )
        return end_timestamp

    def get_current_claimable_distribution_root(self) -> Dict[str, Any]:

        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        raw_data = (
            self.reward_cordinator.functions.getCurrentClaimableDistributionRoot().call()
        )

        distribution_root = {
            "root": raw_data[0],
            "startBlock": raw_data[1],
            "endBlock": raw_data[2],
            "totalClaimable": raw_data[3],
            # Add any additional fields if the struct has more.
        }

        return distribution_root

    def get_root_index_from_hash(self, root_hash: bytes) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        # Call the contract function
        root_index = self.reward_cordinator.functions.getRootIndexFromHash(
            root_hash
        ).call()

        # The Go code returns a uint32; in Python we handle it simply as int.
        return root_index

    def get_cumulative_claimed(self, earner: Address, token: Address) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        claimed_amount = self.reward_cordinator.functions.cumulativeClaimed(
            earner, token
        ).call()

        return claimed_amount

    def check_claim(self, claim: Dict[str, Any]) -> bool:

        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        claim_tuple = (
            claim["root"],  # bytes32
            claim["index"],  # uint256
            claim["account"],  # address
            claim["amount"],  # uint256
            claim["merkleProof"],  # bytes32[]
        )

        try:
            # In Go: r.rewardsCoordinator.CheckClaim(&bind.CallOpts{Context: ctx}, claim)
            # In Python/web3.py, we call the same function with the struct tuple
            is_valid = self.reward_cordinator.functions.checkClaim(claim_tuple).call()
        except Exception:
            # If the contract call reverts or fails, treat it as an invalid claim
            return False

        return is_valid

    def get_operator_avs_split(self, operator: Address, avs: Address) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        # Call the contract function (uint16 in Solidity, Python will treat it as int)
        avs_split = self.reward_cordinator.functions.getOperatorAVSSplit(
            operator, avs
        ).call()

        return avs_split

    def get_operator_pi_split(self, operator: Address) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        pi_split = self.reward_cordinator.functions.getOperatorPISplit(operator).call()
        return pi_split

    def get_operator_set_split(self, operator: Address, operator_set: dict) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        # ✅ Correct order: (AVS Address, ID)
        operator_set_tuple = (operator_set["avs"], operator_set["id"])  # FIXED ORDER

        op_set_split = self.reward_cordinator.functions.getOperatorSetSplit(
            operator, operator_set_tuple  # ✅ Now correctly formatted
        ).call()

        return op_set_split

    def get_rewards_updater(self) -> Address:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        rewards_updater = self.reward_cordinator.functions.rewardsUpdater().call()
        return rewards_updater

    def GetActivationDelay(self) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        activation_delay = self.reward_cordinator.functions.activationDelay().call()
        return activation_delay

    def get_curr_rewards_calculation_end_timestamp(self) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        end_timestamp = (
            self.reward_cordinator.functions.currRewardsCalculationEndTimestamp().call()
        )
        return end_timestamp

    def get_default_operator_split_bips(self) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        default_split_bips = (
            self.reward_cordinator.functions.defaultOperatorSplitBips().call()
        )
        return default_split_bips

    def get_claimer_for(self, earner: Address) -> Address:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        claimer_address = self.reward_cordinator.functions.claimerFor(earner).call()
        return claimer_address

    def get_submission_nonce(self, avs: Address) -> int:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        submission_nonce = self.reward_cordinator.functions.submissionNonce(avs).call()
        return submission_nonce

    def get_is_avs_rewards_submission_hash(self, avs: Address, hash: bytes) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_valid = self.reward_cordinator.functions.isAVSRewardsSubmissionHash(
            avs, hash
        ).call()

        return is_valid

    def get_is_rewards_submission_for_all_hash(self, avs: Address, hash: bytes) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_valid = self.reward_cordinator.functions.isRewardsSubmissionForAllHash(
            avs, hash
        ).call()
        return is_valid

    def get_is_rewards_for_all_submitter(self, submitter: Address) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_authorized = self.reward_cordinator.functions.isRewardsForAllSubmitter(
            submitter
        ).call()
        return is_authorized

    def get_is_rewards_submission_for_all_earners_hash(
        self, avs: Address, hash: bytes
    ) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_valid = (
            self.reward_cordinator.functions.isRewardsSubmissionForAllEarnersHash(
                avs, hash
            ).call()
        )

        return is_valid

    def get_is_operator_directed_avs_rewards_submission_hash(
        self, avs: Address, hash: bytes
    ) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_valid = (
            self.reward_cordinator.functions.isOperatorDirectedAVSRewardsSubmissionHash(
                avs, hash
            ).call()
        )

        return is_valid

    def get_is_operator_directed_operator_set_rewards_submission_hash(
        self, avs: Address, hash: bytes
    ) -> bool:
        if self.reward_cordinator is None:
            raise ValueError("RewardsCoordinator contract not provided")

        is_valid = self.reward_cordinator.functions.isOperatorDirectedOperatorSetRewardsSubmissionHash(
            avs, hash
        ).call()

        return is_valid

    def get_strategy_and_underlying_token(
        self, strategy_addr: str
    ) -> Tuple[Optional[Contract], Optional[str], Optional[Exception]]:
        try:
            # Use eth_http_client instead of web3
            strategy_contract = self.eth_http_client.eth.contract(
                address=strategy_addr, abi=self.strategy_abi
            )
            underlying_token_addr = strategy_contract.functions.underlyingToken().call()
            return strategy_contract, underlying_token_addr, None
        except Exception as e:
            return None, None, e

    def get_strategy_and_underlying_erc20_token(
        self, strategy_addr: str
    ) -> Tuple[
        Optional[Contract], Optional[Contract], Optional[str], Optional[Exception]
    ]:
        try:
            # Load Strategy Contract
            strategy_contract = self.eth_http_client.eth.contract(
                address=strategy_addr, abi=self.strategy_abi
            )

            # Fetch Underlying Token Address
            underlying_token_addr = strategy_contract.functions.underlyingToken().call()

            # Load ERC20 Contract for Underlying Token
            underlying_token_contract = self.eth_http_client.eth.contract(
                address=underlying_token_addr, abi=self.erc20_abi
            )

            return (
                strategy_contract,
                underlying_token_contract,
                underlying_token_addr,
                None,
            )

        except Exception as e:
            return None, None, None, e

    def calculate_operator_avs_registration_digest_hash(
        self, operator: str, avs: str, salt: bytes, expiry: int
    ) -> Tuple[Optional[bytes], Optional[Exception]]:

        if self.avs_directory is None:
            return None, ValueError("AVSDirectory contract not provided")

        try:
            digest_hash = (
                self.avs_directory.functions.calculateOperatorAVSRegistrationDigestHash(
                    operator, avs, salt, expiry
                ).call()
            )
            return digest_hash, None
        except Exception as e:
            return None, e

    def get_calculation_interval_seconds(
        self,
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            interval_seconds = (
                self.reward_cordinator.functions.CALCULATION_INTERVAL_SECONDS().call()
            )
            return interval_seconds, None
        except Exception as e:
            return None, e

    def get_max_rewards_duration(self) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            max_rewards_duration = (
                self.reward_cordinator.functions.MAX_REWARDS_DURATION().call()
            )
            return max_rewards_duration, None
        except Exception as e:
            return None, e

    def get_max_retroactive_length(self) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            max_retroactive_length = (
                self.reward_cordinator.functions.MAX_RETROACTIVE_LENGTH().call()
            )
            return max_retroactive_length, None
        except Exception as e:
            return None, e

    def get_max_future_length(self) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            max_future_length = (
                self.reward_cordinator.functions.MAX_FUTURE_LENGTH().call()
            )
            return max_future_length, None
        except Exception as e:
            return None, e

    def get_genesis_rewards_timestamp(
        self,
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            genesis_rewards_timestamp = (
                self.reward_cordinator.functions.GENESIS_REWARDS_TIMESTAMP().call()
            )
            return genesis_rewards_timestamp, None
        except Exception as e:
            return None, e

    def get_activation_delay(self) -> Tuple[Optional[int], Optional[Exception]]:
        if self.reward_cordinator is None:
            return None, ValueError("RewardsCoordinator contract not provided")

        try:
            activation_delay = self.reward_cordinator.functions.activationDelay().call()
            return activation_delay, None
        except Exception as e:
            return None, e

    def get_deallocation_delay(self) -> Tuple[Optional[int], Optional[Exception]]:
        if self.allocation_manager is None:
            return None, ValueError("AllocationManager contract not provided")

        try:
            deallocation_delay = (
                self.allocation_manager.functions.DEALLOCATION_DELAY().call()
            )
            return deallocation_delay, None
        except Exception as e:
            return None, e

    def get_allocation_configuration_delay(
        self,
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.allocation_manager is None:
            return None, ValueError("AllocationManager contract not provided")

        try:
            allocation_configuration_delay = (
                self.allocation_manager.functions.ALLOCATION_CONFIGURATION_DELAY().call()
            )
            return allocation_configuration_delay, None
        except Exception as e:
            return None, e

    def get_num_operator_sets_for_operator(
        self, operator_address: str
    ) -> Tuple[Optional[int], Optional[Exception]]:
        if self.allocation_manager is None:
            return None, ValueError("AllocationManager contract not provided")

        try:
            op_sets = self.allocation_manager.functions.getAllocatedSets(
                operator_address
            ).call()
            return len(op_sets), None
        except Exception as e:
            return None, e

    def get_slashable_shares(
        self, operator_address: str, operator_set, strategies: List[str]
    ) -> Tuple[Optional[Dict[str, int]], Optional[Exception]]:

        if self.allocation_manager is None:
            return None, ValueError("AllocationManager contract not provided")

        try:
            # Get the AVS address safely
            avs_address = operator_set.get("avs") or operator_set.get("AVSAddress")
            if avs_address is None:
                return None, ValueError("Missing 'avs' or 'AVSAddress' in operator_set")

            # Get the current block number using eth_http_client instead of web3
            current_block = self.eth_http_client.eth.block_number

            # Fetch the slashable shares
            slashable_shares = (
                self.allocation_manager.functions.getMinimumSlashableStake(
                    operator_set, [operator_address], strategies, current_block
                ).call()
            )

            if not slashable_shares or len(slashable_shares[0]) == 0:
                return None, ValueError("No slashable shares found for operator")

            # Mapping strategies to their corresponding slashable shares
            slashable_share_strategy_map = {
                strategies[i]: slashable_shares[0][i] for i in range(len(strategies))
            }

            return slashable_share_strategy_map, None

        except Exception as e:
            return None, e

    def test_get_strategy_and_underlying_token(strategy_address):
        """Test get_strategy_and_underlying_token() with a deployed Anvil contract."""

        try:
            # Call the function
            strategy_contract, underlying_token_addr, error = (
                el_reader.get_strategy_and_underlying_token(strategy_address)
            )

            # Assertions
            assert error is None, f"\n❌ Unexpected error: {error}"
            assert (
                strategy_contract is not None
            ), "\n❌ Expected a valid strategy contract, got None"
            assert (
                underlying_token_addr is not None
            ), "\n❌ Expected a valid underlying token address, got None"
            assert isinstance(
                underlying_token_addr, str
            ), f"\n❌ Expected underlying token address to be a string, but got {type(underlying_token_addr)}"

            # Print output for debugging
            print(f"\n✅ Strategy Contract: {strategy_contract}")
            print(f"✅ Underlying Token Address: {underlying_token_addr}")

        except Exception as e:
            pytest.fail(f"\n❌ Test failed due to unexpected error: {e}")

    def get_slashable_shares_for_operator_sets_before(
        self, operator_sets: List[Dict], future_block: int
    ) -> Tuple[Optional[List[Dict]], Optional[Exception]]:

        if self.allocation_manager is None:
            return None, ValueError("AllocationManager contract not provided")

        operator_set_stakes = []
        try:
            for operator_set in operator_sets:
                # Ensure correct key format
                if "Id" not in operator_set and "id" in operator_set:
                    operator_set["Id"] = operator_set.pop(
                        "id"
                    )  # Rename key to match expected format
                # Debugging: Log received operator set
                print(f"🔍 Processing OperatorSet: {operator_set}")

                # Validate structure
                if "Id" not in operator_set or "Avs" not in operator_set:
                    return None, ValueError(
                        f"Invalid operator_set format: {operator_set}"
                    )
                set_id = int(operator_set["Id"])
                avs_address = operator_set["Avs"]

                if set_id == 0:
                    return None, ValueError(
                        f"Legacy AVSs not supported (operatorSet.Id == 0)"
                    )
                # Fetch operators
                operators = self.get_operators_for_operator_set(operator_set)
                # Debugging: Print what we retrieved
                print(f"🔍 Retrieved Operators for {set_id}: {operators}")

                if not operators:
                    return None, ValueError(
                        f"Failed to get operators for OperatorSet: {operator_set}"
                    )

                # Fetch strategies
                strategies = self.get_strategies_for_operator_set(operator_set)

                # Debugging: Print what we retrieved
                print(f"🔍 Retrieved Strategies for {set_id}: {strategies}")

                if not strategies:
                    return None, ValueError(
                        f"Failed to get strategies for OperatorSet: {operator_set}"
                    )

                # Fetch slashable shares
                try:
                    slashable_shares = (
                        self.allocation_manager.functions.getMinimumSlashableStake(
                            {"Id": set_id, "Avs": avs_address},
                            operators,
                            strategies,
                            future_block,
                        ).call()
                    )
                except Exception as e:
                    return None, ValueError(f"Failed to fetch slashable shares: {e}")

                # Store results
                operator_set_stakes.append(
                    {
                        "OperatorSet": operator_set,
                        "Strategies": strategies,
                        "Operators": operators,
                        "SlashableStakes": slashable_shares,
                    }
                )

            return operator_set_stakes, None

        except Exception as e:
            return None, e
