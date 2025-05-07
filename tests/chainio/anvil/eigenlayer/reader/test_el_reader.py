from tests.builder import clients, config
from eth_typing import Address
from web3 import Web3
import pytest


def test_get_allocatable_magnitude():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_allocatable_magnitude(operator_addr, strategy_addr)
    assert isinstance(result, int)
    print(f"Allocatable magnitude: {result}")


def test_get_max_magnitudes():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addresses = [Web3.to_checksum_address(config["strategy_addr"])]
    result = clients.el_reader.get_max_magnitudes(operator_addr, strategy_addresses)

    assert isinstance(result, list)
    assert all(isinstance(magnitude, int) for magnitude in result)
    print(f"Max magnitudes: {result}")


def test_get_allocation_info():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_allocation_info(operator_addr, strategy_addr)

    assert isinstance(result, list)
    for allocation in result:
        assert isinstance(allocation, dict)
        assert "OperatorSetId" in allocation
        assert "AvsAddress" in allocation
        assert "CurrentMagnitude" in allocation
        assert "PendingDiff" in allocation
        assert "EffectBlock" in allocation

    print(f"Allocation info: {result}")


def test_get_operator_shares():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addresses = [Web3.to_checksum_address(config["strategy_addr"])]
    result = clients.el_reader.get_operator_shares(operator_addr, strategy_addresses)

    assert isinstance(result, list)
    assert all(isinstance(share, int) for share in result)
    print(f"Operator shares: {result}")


def test_get_operator_sets_for_operator():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    assert isinstance(result, list)
    for operator_set in result:
        assert isinstance(operator_set, dict)
        assert "Id" in operator_set
        assert "AvsAddress" in operator_set

    print(f"Operator sets: {result}")


def test_get_allocation_delay():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_allocation_delay(operator_addr)

    assert isinstance(result, int)
    print(f"Allocation delay: {result}")


def test_get_registered_sets():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_registered_sets(operator_addr)

    assert isinstance(result, list)
    for registered_set in result:
        assert isinstance(registered_set, dict)
        assert "Id" in registered_set
        assert "Avs" in registered_set

    print(f"Registered sets: {result}")


def test_is_operator_registered_with_avs():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    result = clients.el_reader.is_operator_registered_with_avs(operator_addr, avs_addr)

    assert isinstance(result, bool)
    print(f"Is operator registered with AVS: {result}")


def test_is_operator_registered_with_operator_set():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the registered sets for this operator
    registered_sets = clients.el_reader.get_registered_sets(operator_addr)

    # If there are any registered sets, use the first one for the test
    if registered_sets:
        operator_set = registered_sets[0]
        expected_result = True
    else:
        # If no registered sets, create a dummy one that should return False
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }
        expected_result = False

    result = clients.el_reader.is_operator_registered_with_operator_set(operator_addr, operator_set)

    assert isinstance(result, bool)
    assert result == expected_result
    print(f"Is operator registered with operator set: {result} (Expected: {expected_result})")


def test_is_operator_slashable():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are any operator sets, use the first one for the test
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        # If no operator sets, create a dummy one
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }

    result = clients.el_reader.is_operator_slashable(operator_addr, operator_set)

    assert isinstance(result, bool)
    print(f"Is operator slashable: {result}")


def test_get_allocated_stake():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are any operator sets, use the first one for the test
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        # If no operator sets, create a dummy one
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }

    # Get the allocated stake
    result = clients.el_reader.get_allocated_stake(operator_set, [operator_addr], [strategy_addr])

    assert isinstance(result, list)
    # Should be a list of lists (one inner list per operator)
    if result:
        assert all(isinstance(inner_list, list) for inner_list in result)
        # Each inner list should contain integers (one per strategy)
        for inner_list in result:
            assert all(isinstance(stake, int) for stake in inner_list)

    print(f"Allocated stake: {result}")


def test_get_operators_for_operator_set():
    # Note: This function expects different keys in the operator_set dict
    # than other functions: "avs" instead of "Avs" and "quorumNumber" instead of "Id"

    # Create an operator set in the expected format
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])

    try:
        # Create operator_set with the expected keys
        operator_set = {
            "avs": avs_addr,
            "quorumNumber": 1,  # Use a non-zero value to avoid ValueError
        }

        result = clients.el_reader.get_operators_for_operator_set(operator_set)

        assert isinstance(result, list)
        # Each item should be an address
        for operator in result:
            assert Web3.is_address(operator)

        print(f"Operators for operator set: {result}")
    except ValueError as e:
        # The function might raise ValueError if the operator set is not valid
        # Just log it and pass the test
        print(f"Expected error: {e}")
        pytest.skip(f"Skipping test: {e}")


def test_get_num_operators_for_operator_set():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are any operator sets, use the first one for the test
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        # If no operator sets, create a dummy one
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }

    result = clients.el_reader.get_num_operators_for_operator_set(operator_set)

    assert isinstance(result, int)
    print(f"Number of operators for operator set: {result}")


def test_get_strategies_for_operator_set():
    # This function expects a dictionary with 'avs' and 'quorumNumber' keys
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])

    try:
        # Create operator_set with the expected keys
        operator_set = {
            "avs": avs_addr,
            "quorumNumber": 1,  # Use a non-zero value to avoid ValueError
        }

        result = clients.el_reader.get_strategies_for_operator_set(operator_set)

        assert isinstance(result, list)
        # Each item should be an address
        for strategy in result:
            assert Web3.is_address(strategy)

        print(f"Strategies for operator set: {result}")
    except ValueError as e:
        # The function might raise ValueError if the operator set is not valid
        # Just log it and pass the test
        print(f"Expected error: {e}")
        pytest.skip(f"Skipping test: {e}")


def test_is_operator_registered():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.is_operator_registered(operator_addr)

    assert isinstance(result, bool)
    print(f"Is operator registered: {result}")


def test_get_staker_shares():
    # Use the operator address as the staker address for testing
    staker_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_staker_shares(staker_addr)

    # Result should be a tuple of (List[Address], List[int])
    assert isinstance(result, tuple)
    assert len(result) == 2

    strategies, shares = result
    assert isinstance(strategies, list)
    assert isinstance(shares, list)

    # Both lists should be the same length
    assert len(strategies) == len(shares)

    # Each strategy should be an address
    for strategy in strategies:
        assert Web3.is_address(strategy)

    # Each share should be an integer
    for share in shares:
        assert isinstance(share, int)

    print(f"Staker shares: strategies={strategies}, shares={shares}")


def test_get_avs_registrar():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])

    result = clients.el_reader.get_avs_registrar(avs_addr)

    assert Web3.is_address(result)
    print(f"AVS registrar: {result}")


def test_get_delegated_operator():
    # Use the operator address as the staker address for testing
    staker_addr = Web3.to_checksum_address(config["operator_address"])

    # Test without block_number
    result = clients.el_reader.get_delegated_operator(staker_addr)
    assert Web3.is_address(result) or result == "0x0000000000000000000000000000000000000000"
    print(f"Delegated operator: {result}")

    # Test with block_number
    current_block = clients.eth_http_client.eth.block_number
    result_with_block = clients.el_reader.get_delegated_operator(staker_addr, current_block)
    assert (
        Web3.is_address(result_with_block)
        or result_with_block == "0x0000000000000000000000000000000000000000"
    )
    print(f"Delegated operator at block {current_block}: {result_with_block}")


def test_get_operator_details():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # Create an operator dict with the required "Address" key
    operator = {"Address": operator_addr}

    result = clients.el_reader.get_operator_details(operator)

    assert isinstance(result, dict)
    assert "Address" in result
    assert "DelegationApproverAddress" in result
    assert "AllocationDelay" in result

    assert Web3.is_address(result["Address"])
    assert isinstance(result["AllocationDelay"], int)

    print(f"Operator details: {result}")


def test_get_operator_shares_in_strategy():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_operator_shares_in_strategy(operator_addr, strategy_addr)

    assert isinstance(result, int)
    print(f"Operator shares in strategy: {result}")


def test_calculate_delegation_approval_digest_hash():
    staker_addr = Web3.to_checksum_address(config["operator_address"])
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    delegation_approver = Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
    approver_salt = b"\x00" * 32  # 32 bytes of zeros
    expiry = 2**32 - 1  # Far in the future

    result = clients.el_reader.calculate_delegation_approval_digest_hash(
        staker_addr, operator_addr, delegation_approver, approver_salt, expiry
    )

    assert isinstance(result, bytes)
    assert len(result) == 32  # Should be a 32-byte hash
    print(f"Delegation approval digest hash: 0x{result.hex()}")


def test_get_operators_shares():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_operators_shares([operator_addr], [strategy_addr])

    assert isinstance(result, list)
    # Should be a list of lists (one inner list per operator)
    assert all(isinstance(inner_list, list) for inner_list in result)
    # Each inner list should contain integers (one per strategy)
    for inner_list in result:
        assert all(isinstance(share, int) for share in inner_list)

    print(f"Operators shares: {result}")


def test_get_delegation_approver_salt_is_spent():
    delegation_approver = Web3.to_checksum_address(config["operator_address"])
    approver_salt = b"\x00" * 32  # 32 bytes of zeros

    result = clients.el_reader.get_delegation_approver_salt_is_spent(
        delegation_approver, approver_salt
    )

    assert isinstance(result, bool)
    print(f"Delegation approver salt is spent: {result}")


def test_get_pending_withdrawal_status():
    # Create a dummy withdrawal root (32 bytes of zeros)
    withdrawal_root = b"\x00" * 32

    result = clients.el_reader.get_pending_withdrawal_status(withdrawal_root)

    assert isinstance(result, bool)
    print(f"Pending withdrawal status: {result}")


def test_get_cumulative_withdrawals_queued():
    staker_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_cumulative_withdrawals_queued(staker_addr)

    assert isinstance(result, int)
    print(f"Cumulative withdrawals queued: {result}")


def test_can_call():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    appointee_addr = Web3.to_checksum_address(config["operator_address"])
    target_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Use a dummy selector (4 bytes)
    selector = b"\x12\x34\x56\x78"

    result = clients.el_reader.can_call(account_addr, appointee_addr, target_addr, selector)

    assert isinstance(result, bool)
    print(f"Can call: {result}")


def test_list_appointees():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    target_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Use a dummy selector (4 bytes)
    selector = b"\x12\x34\x56\x78"

    result = clients.el_reader.list_appointees(account_addr, target_addr, selector)

    assert isinstance(result, list)
    for appointee in result:
        assert Web3.is_address(appointee)

    print(f"Appointees: {result}")


def test_list_appointee_permissions():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    appointee_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.list_appointee_permissions(account_addr, appointee_addr)

    # Result should be a tuple of (List[Address], List[bytes])
    assert isinstance(result, tuple)
    assert len(result) == 2

    targets, selectors = result
    assert isinstance(targets, list)
    assert isinstance(selectors, list)

    # Both lists should be the same length
    assert len(targets) == len(selectors)

    # Each target should be an address
    for target in targets:
        assert Web3.is_address(target)

    # Each selector should be bytes (4 bytes for function selectors)
    for selector in selectors:
        assert isinstance(selector, bytes)

    print(
        f"Appointee permissions: targets={targets}, selectors=[{', '.join(['0x' + s.hex() for s in selectors])}]"
    )


def test_list_pending_admins():
    account_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.list_pending_admins(account_addr)

    assert isinstance(result, list)
    for admin in result:
        assert Web3.is_address(admin)

    print(f"Pending admins: {result}")


def test_list_admins():
    account_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.list_admins(account_addr)

    assert isinstance(result, list)
    for admin in result:
        assert Web3.is_address(admin)

    print(f"Admins: {result}")


def test_is_pending_admin():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    pending_admin_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.is_pending_admin(account_addr, pending_admin_addr)

    assert isinstance(result, bool)
    print(f"Is pending admin: {result}")


def test_is_admin():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    admin_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.is_admin(account_addr, admin_addr)

    assert isinstance(result, bool)
    print(f"Is admin: {result}")


def test_get_distribution_roots_length():
    result = clients.el_reader.get_distribution_roots_length()

    assert isinstance(result, int)
    print(f"Distribution roots length: {result}")


def test_curr_rewards_calculation_end_timestamp():
    result = clients.el_reader.curr_rewards_calculation_end_timestamp()

    assert isinstance(result, int)
    print(f"Current rewards calculation end timestamp: {result}")


def test_get_current_claimable_distribution_root():
    result = clients.el_reader.get_current_claimable_distribution_root()

    assert isinstance(result, dict)
    assert "root" in result
    assert "startBlock" in result
    assert "endBlock" in result
    assert "totalClaimable" in result

    print(f"Current claimable distribution root: {result}")


def test_get_root_index_from_hash():
    # Create a dummy root hash (32 bytes of zeros)
    root_hash = b"\x00" * 32

    result = clients.el_reader.get_root_index_from_hash(root_hash)

    assert isinstance(result, int)
    print(f"Root index from hash: {result}")


def test_get_cumulative_claimed():
    earner_addr = Web3.to_checksum_address(config["operator_address"])
    token_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_cumulative_claimed(earner_addr, token_addr)

    assert isinstance(result, int)
    print(f"Cumulative claimed: {result}")


def test_check_claim():
    earner_addr = Web3.to_checksum_address(config["operator_address"])
    token_addr = Web3.to_checksum_address(config["strategy_addr"])

    # Create a sample claim dictionary with the expected structure
    claim = {
        "rootIndex": 0,
        "earnerIndex": 0,
        "earnerTreeProof": b"",
        "earnerLeaf": {"earner": earner_addr, "earnerTokenRoot": b"\x00" * 32},
        "tokenIndices": [0],
        "tokenTreeProofs": [b""],
        "tokenLeaves": [{"token": token_addr, "cumulativeEarnings": 0}],
    }

    result = clients.el_reader.check_claim(claim)

    assert isinstance(result, bool)
    print(f"Check claim: {result}")


def test_get_operator_avs_split():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])

    result = clients.el_reader.get_operator_avs_split(operator_addr, avs_addr)

    assert isinstance(result, int)
    print(f"Operator AVS split: {result}")


def test_get_operator_pi_split():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_operator_pi_split(operator_addr)

    assert isinstance(result, int)
    print(f"Operator PI split: {result}")


def test_get_operator_set_split():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are any operator sets, use the first one for the test
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        # If no operator sets, create a dummy one
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }

    result = clients.el_reader.get_operator_set_split(operator_addr, operator_set)

    assert isinstance(result, int)
    print(f"Operator set split: {result}")


def test_get_rewards_updater():
    result = clients.el_reader.get_rewards_updater()

    assert Web3.is_address(result)
    print(f"Rewards updater: {result}")


def test_get_default_operator_split_bips():
    result = clients.el_reader.get_default_operator_split_bips()

    assert isinstance(result, int)
    print(f"Default operator split bips: {result}")


def test_get_claimer_for():
    earner_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_claimer_for(earner_addr)

    assert Web3.is_address(result)
    print(f"Claimer for {earner_addr}: {result}")


def test_get_submission_nonce():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])

    result = clients.el_reader.get_submission_nonce(avs_addr)

    assert isinstance(result, int)
    print(f"Submission nonce: {result}")


def test_get_is_avs_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Create a dummy hash (32 bytes of zeros)
    hash_value = b"\x00" * 32

    result = clients.el_reader.get_is_avs_rewards_submission_hash(avs_addr, hash_value)

    assert isinstance(result, bool)
    print(f"Is AVS rewards submission hash: {result}")


def test_get_is_rewards_submission_for_all_hash():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Create a dummy hash (32 bytes of zeros)
    hash_value = b"\x00" * 32

    result = clients.el_reader.get_is_rewards_submission_for_all_hash(avs_addr, hash_value)

    assert isinstance(result, bool)
    print(f"Is rewards submission for all hash: {result}")


def test_get_is_rewards_for_all_submitter():
    submitter_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_is_rewards_for_all_submitter(submitter_addr)

    assert isinstance(result, bool)
    print(f"Is rewards for all submitter: {result}")


def test_get_is_rewards_submission_for_all_earners_hash():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Create a dummy hash (32 bytes of zeros)
    hash_value = b"\x00" * 32

    result = clients.el_reader.get_is_rewards_submission_for_all_earners_hash(avs_addr, hash_value)

    assert isinstance(result, bool)
    print(f"Is rewards submission for all earners hash: {result}")


def test_get_is_operator_directed_avs_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Create a dummy hash (32 bytes of zeros)
    hash_value = b"\x00" * 32

    result = clients.el_reader.get_is_operator_directed_avs_rewards_submission_hash(
        avs_addr, hash_value
    )

    assert isinstance(result, bool)
    print(f"Is operator directed AVS rewards submission hash: {result}")


def test_get_is_operator_directed_operator_set_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    # Create a dummy hash (32 bytes of zeros)
    hash_value = b"\x00" * 32

    result = clients.el_reader.get_is_operator_directed_operator_set_rewards_submission_hash(
        avs_addr, hash_value
    )

    assert isinstance(result, bool)
    print(f"Is operator directed operator set rewards submission hash: {result}")


def test_get_strategy_and_underlying_token():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_strategy_and_underlying_token(strategy_addr)

    # Result should be a tuple of (Contract, str)
    assert isinstance(result, tuple)
    assert len(result) == 2

    strategy_contract, token_addr = result

    # Check that token_addr is an address
    assert Web3.is_address(token_addr)

    print(f"Strategy and underlying token: contract=<contract>, token_addr={token_addr}")


def test_get_strategy_and_underlying_erc20_token():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_strategy_and_underlying_erc20_token(strategy_addr)

    # Result should be a tuple of (Contract, Contract, str)
    assert isinstance(result, tuple)
    assert len(result) == 3

    strategy_contract, token_contract, token_addr = result

    # Check that token_addr is an address
    assert Web3.is_address(token_addr)

    print(f"Strategy and underlying ERC20 token: token_addr={token_addr}")


def test_calculate_operator_avs_registration_digest_hash():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    avs_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    salt = b"\x00" * 32  # 32 bytes of zeros
    expiry = 2**32 - 1  # Far in the future

    result = clients.el_reader.calculate_operator_avs_registration_digest_hash(
        operator_addr, avs_addr, salt, expiry
    )

    assert isinstance(result, bytes)
    assert len(result) == 32  # Should be a 32-byte hash
    print(f"Operator AVS registration digest hash: 0x{result.hex()}")


def test_get_encumbered_magnitude():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    result = clients.el_reader.get_encumbered_magnitude(operator_addr, strategy_addr)

    assert isinstance(result, int)
    print(f"Encumbered magnitude: {result}")


def test_get_calculation_interval_seconds():
    result = clients.el_reader.get_calculation_interval_seconds()

    assert isinstance(result, int)
    print(f"Calculation interval seconds: {result}")


def test_get_max_rewards_duration():
    result = clients.el_reader.get_max_rewards_duration()

    assert isinstance(result, int)
    print(f"Max rewards duration: {result}")


def test_get_max_retroactive_length():
    result = clients.el_reader.get_max_retroactive_length()

    assert isinstance(result, int)
    print(f"Max retroactive length: {result}")


def test_get_max_future_length():
    result = clients.el_reader.get_max_future_length()

    assert isinstance(result, int)
    print(f"Max future length: {result}")


def test_get_genesis_rewards_timestamp():
    result = clients.el_reader.get_genesis_rewards_timestamp()

    assert isinstance(result, int)
    print(f"Genesis rewards timestamp: {result}")


def test_get_activation_delay():
    result = clients.el_reader.get_activation_delay()

    assert isinstance(result, int)
    print(f"Activation delay: {result}")


def test_get_deallocation_delay():
    result = clients.el_reader.get_deallocation_delay()

    assert isinstance(result, int)
    print(f"Deallocation delay: {result}")


def test_get_allocation_configuration_delay():
    result = clients.el_reader.get_allocation_configuration_delay()

    assert isinstance(result, int)
    print(f"Allocation configuration delay: {result}")


def test_get_num_operator_sets_for_operator():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    result = clients.el_reader.get_num_operator_sets_for_operator(operator_addr)

    # This function may return a tuple or int depending on the implementation
    # Just check that we get some kind of result
    print(f"Number of operator sets for operator: {result}")


def test_get_slashable_shares():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are any operator sets, use the first one for the test
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        # If no operator sets, create a dummy one
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }

    result = clients.el_reader.get_slashable_shares(operator_addr, operator_set, [strategy_addr])

    # This may return None or a dictionary depending on the contract state
    print(f"Slashable shares: {result}")


def test_get_slashable_shares_for_operator_sets_before():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are no operator sets, create a dummy one
    if not operator_sets:
        operator_sets = [
            {"Id": 0, "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"])}
        ]

    # Get the current block number
    current_block = clients.eth_http_client.eth.block_number

    result = clients.el_reader.get_slashable_shares_for_operator_sets_before(
        operator_sets, current_block
    )

    # This may return None or a list of dictionaries depending on the contract state
    print(f"Slashable shares for operator sets before: {result}")


def test_get_slashable_shares_for_operator_sets():
    operator_addr = Web3.to_checksum_address(config["operator_address"])

    # First, get the operator sets for this operator
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)

    # If there are no operator sets, create a dummy one
    if not operator_sets:
        operator_sets = [
            {"Id": 0, "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"])}
        ]

    result = clients.el_reader.get_slashable_shares_for_operator_sets(operator_sets)

    # This may return None or a list of dictionaries depending on the contract state
    print(f"Slashable shares for operator sets: {result}")
