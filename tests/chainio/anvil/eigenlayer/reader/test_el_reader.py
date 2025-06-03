from web3 import Web3

from eigensdk.chainio.utils import nums_to_bytes
from tests.builder import clients, config


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
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    result = clients.el_reader.is_operator_registered_with_avs(operator_addr, avs_addr)
    assert isinstance(result, bool)
    print(f"Is operator registered with AVS: {result}")


def test_is_operator_registered_with_operator_set():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    registered_sets = clients.el_reader.get_registered_sets(operator_addr)
    if registered_sets:
        operator_set = registered_sets[0]
        expected_result = True
    else:
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
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if operator_sets:
        operator_set = operator_sets[0]
    else:
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
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }
    result = clients.el_reader.get_allocated_stake(operator_set, [operator_addr], [strategy_addr])
    assert isinstance(result, list)
    if result:
        assert all(isinstance(inner_list, list) for inner_list in result)
        for inner_list in result:
            assert all(isinstance(stake, int) for stake in inner_list)
    print(f"Allocated stake: {result}")


def test_get_operators_for_operator_set():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    operator_set = {"id": 1, "avs": avs_addr, "quorumNumber": 1}
    result = clients.el_reader.get_operators_for_operator_set(operator_set)
    assert isinstance(result, list)
    for operator in result:
        assert Web3.is_address(operator)
    print(f"Operators for operator set: {result}")


def test_get_num_operators_for_operator_set():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        operator_set = {
            "Id": 0,
            "Avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }
    result = clients.el_reader.get_num_operators_for_operator_set(operator_set)
    assert isinstance(result, int)
    print(f"Number of operators for operator set: {result}")


def test_get_strategies_for_operator_set():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    operator_set = {"id": 1, "avs": avs_addr, "quorumNumber": 1}
    result = clients.el_reader.get_strategies_for_operator_set(operator_set)
    assert isinstance(result, list)
    for strategy in result:
        assert Web3.is_address(strategy)
    print(f"Strategies for operator set: {result}")


def test_is_operator_registered():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.is_operator_registered(operator_addr)
    assert isinstance(result, bool)
    print(f"Is operator registered: {result}")


def test_get_staker_shares():
    staker_addr = Web3.to_checksum_address(config["operator_address"])
    strategies, shares = clients.el_reader.get_staker_shares(staker_addr)
    assert isinstance(strategies, list)
    assert isinstance(shares, list)
    assert len(strategies) == len(shares)
    for strategy in strategies:
        assert Web3.is_address(strategy)
    for share in shares:
        assert isinstance(share, int)
    print(f"Staker shares: strategies={strategies}, shares={shares}")


def test_get_avs_registrar():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    result = clients.el_reader.get_avs_registrar(avs_addr)
    assert Web3.is_address(result)
    print(f"AVS registrar: {result.hex() if isinstance(result, bytes) else result}")


def test_get_delegated_operator():
    staker_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_delegated_operator(staker_addr)
    assert Web3.is_address(result) or result == "0x0000000000000000000000000000000000000000"
    print(f"Delegated operator: {result.hex() if isinstance(result, bytes) else result}")
    current_block = clients.eth_http_client.eth.block_number
    result_with_block = clients.el_reader.get_delegated_operator(staker_addr, current_block)
    assert (
        Web3.is_address(result_with_block)
        or result_with_block == "0x0000000000000000000000000000000000000000"
    )
    print(f"Delegated operator at block {current_block}: {result_with_block.hex() if isinstance(result_with_block, bytes) else result_with_block}")


def test_get_operator_details():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
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
    approver_salt = nums_to_bytes([0] * 32)
    expiry = 2**32 - 1
    result = clients.el_reader.calculate_delegation_approval_digest_hash(
        staker_addr, operator_addr, delegation_approver, approver_salt, expiry
    )
    assert isinstance(result, bytes)
    assert len(result) == 32
    print(f"Delegation approval digest hash: 0x{result.hex()}")


def test_get_operators_shares():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_operators_shares([operator_addr], [strategy_addr])
    assert isinstance(result, list)
    assert all(isinstance(inner_list, list) for inner_list in result)
    for inner_list in result:
        assert all(isinstance(share, int) for share in inner_list)
    print(f"Operators shares: {result}")


def test_get_delegation_approver_salt_is_spent():
    delegation_approver = Web3.to_checksum_address(config["operator_address"])
    approver_salt = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_delegation_approver_salt_is_spent(
        delegation_approver, approver_salt
    )
    assert isinstance(result, bool)
    print(f"Delegation approver salt is spent: {result}")


def test_get_pending_withdrawal_status():
    withdrawal_root = nums_to_bytes([0] * 32)
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
    selector = nums_to_bytes([12, 34, 56, 78])
    result = clients.el_reader.can_call(account_addr, appointee_addr, target_addr, selector)
    assert isinstance(result, bool)
    print(f"Can call: {result}")


def test_list_appointees():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    target_addr = Web3.to_checksum_address(config["avs_registry_coordinator_address"])
    selector = nums_to_bytes([12, 34, 56, 78])
    result = clients.el_reader.list_appointees(account_addr, target_addr, selector)
    assert isinstance(result, list)
    for appointee in result:
        assert Web3.is_address(appointee)
    print(f"Appointees: {result}")


def test_list_appointee_permissions():
    account_addr = Web3.to_checksum_address(config["operator_address"])
    appointee_addr = Web3.to_checksum_address(config["operator_address"])
    targets, selectors = clients.el_reader.list_appointee_permissions(account_addr, appointee_addr)
    assert len(targets) == len(selectors)
    for target in targets:
        assert Web3.is_address(target)
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


def test_get_curr_rewards_calculation_end_timestamp():
    result = clients.el_reader.get_curr_rewards_calculation_end_timestamp()
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


def test_get_cumulative_claimed():
    earner_addr = Web3.to_checksum_address(config["operator_address"])
    token_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_cumulative_claimed(earner_addr, token_addr)
    assert isinstance(result, int)
    print(f"Cumulative claimed: {result}")


def test_get_operator_avs_split():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    avs_addr = Web3.to_checksum_address(config["avs_address"])
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
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if operator_sets:
        operator_set = operator_sets[0]
    else:
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
    print(f"Rewards updater: {result.hex() if isinstance(result, bytes) else result}")


def test_get_default_operator_split_bips():
    result = clients.el_reader.get_default_operator_split_bips()
    assert isinstance(result, int)
    print(f"Default operator split bips: {result}")


def test_get_claimer_for():
    earner_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_claimer_for(earner_addr)
    assert Web3.is_address(result)
    print(f"Claimer for {earner_addr}: {result.hex() if isinstance(result, bytes) else result}")


def test_get_submission_nonce():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    result = clients.el_reader.get_submission_nonce(avs_addr)
    assert isinstance(result, int)
    print(f"Submission nonce: {result}")


def test_get_is_avs_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    hash_value = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_is_avs_rewards_submission_hash(avs_addr, hash_value)
    assert isinstance(result, bool)
    print(f"Is AVS rewards submission hash: {result}")


def test_get_is_rewards_submission_for_all_hash():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    hash_value = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_is_rewards_submission_for_all_hash(avs_addr, hash_value)
    assert isinstance(result, bool)
    print(f"Is rewards submission for all hash: {result}")


def test_get_is_rewards_for_all_submitter():
    submitter_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.el_reader.get_is_rewards_for_all_submitter(submitter_addr)
    assert isinstance(result, bool)
    print(f"Is rewards for all submitter: {result}")


def test_get_is_rewards_submission_for_all_earners_hash():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    hash_value = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_is_rewards_submission_for_all_earners_hash(avs_addr, hash_value)
    assert isinstance(result, bool)
    print(f"Is rewards submission for all earners hash: {result}")


def test_get_is_operator_directed_avs_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    hash_value = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_is_operator_directed_avs_rewards_submission_hash(
        avs_addr, hash_value
    )
    assert isinstance(result, bool)
    print(f"Is operator directed AVS rewards submission hash: {result}")


def test_get_is_operator_directed_operator_set_rewards_submission_hash():
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    hash_value = nums_to_bytes([0] * 32)
    result = clients.el_reader.get_is_operator_directed_operator_set_rewards_submission_hash(
        avs_addr, hash_value
    )
    assert isinstance(result, bool)
    print(f"Is operator directed operator set rewards submission hash: {result}")


def test_get_strategy_and_underlying_token():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_strategy_and_underlying_token(strategy_addr)
    assert isinstance(result, tuple)
    assert len(result) == 2
    strategy_contract, token_addr = result
    assert Web3.is_address(token_addr)
    print(
        f"Strategy and underlying token: contract={strategy_contract.address}, token_addr={token_addr}"
    )


def test_get_strategy_and_underlying_erc20_token():
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    result = clients.el_reader.get_strategy_and_underlying_erc20_token(strategy_addr)
    assert isinstance(result, tuple)
    assert len(result) == 3
    strategy_contract, token_contract, token_addr = result
    assert Web3.is_address(token_addr)
    print(
        f"Strategy and underlying ERC20 token: token_addr={token_addr}, token_contract={token_contract.address}, strategy_contract={strategy_contract.address}"
    )


def test_calculate_operator_avs_registration_digest_hash():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    avs_addr = Web3.to_checksum_address(config["avs_address"])
    salt = nums_to_bytes([0] * 32)
    expiry = 2**32 - 1
    result = clients.el_reader.calculate_operator_avs_registration_digest_hash(
        operator_addr, avs_addr, salt, expiry
    )
    assert isinstance(result, bytes)
    assert len(result) == 32
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
    print(f"Number of operator sets for operator: {result}")


def test_get_slashable_shares():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if operator_sets:
        operator_set = operator_sets[0]
    else:
        operator_set = {
            "id": 0,
            "avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"]),
        }
    result = clients.el_reader.get_slashable_shares(operator_addr, operator_set, [strategy_addr])
    print(f"Slashable shares: {result}")


def test_get_slashable_shares_for_operator_sets_before():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if not operator_sets:
        operator_sets = [
            {"id": 1, "avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"])}
        ]
    current_block = clients.eth_http_client.eth.block_number
    result = clients.el_reader.get_slashable_shares_for_operator_sets_before(
        operator_sets, current_block
    )
    print(f"Slashable shares for operator sets before: {result}")


def test_get_slashable_shares_for_operator_sets():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operator_sets = clients.el_reader.get_operator_sets_for_operator(operator_addr)
    if not operator_sets:
        operator_sets = [
            {"id": 1, "avs": Web3.to_checksum_address(config["avs_registry_coordinator_address"])}
        ]
    result = clients.el_reader.get_slashable_shares_for_operator_sets(operator_sets)
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, dict)
        assert "OperatorSet" in item
        assert "Strategies" in item
        assert "Operators" in item
        assert "SlashableStakes" in item
        operator_set = item["OperatorSet"]
        assert isinstance(operator_set, dict)
        assert "id" in operator_set
        assert "avs" in operator_set
        assert isinstance(operator_set["id"], int)
        assert Web3.is_address(operator_set["avs"])
        assert isinstance(item["Strategies"], list)
        assert isinstance(item["Operators"], list)
        assert isinstance(item["SlashableStakes"], list)
        for strategy in item["Strategies"]:
            assert Web3.is_address(strategy)
        for operator in item["Operators"]:
            assert Web3.is_address(operator)
        for stake in item["SlashableStakes"]:
            assert isinstance(stake, int)
    print(f"Slashable shares for operator sets: {result}")
