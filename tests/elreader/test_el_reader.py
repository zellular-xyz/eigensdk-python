import pytest
from base import *
from web3 import Web3
from conftestreader import *


def test_get_allocatable_magnitude(operator_address, strategy_address):
    result = el_reader.get_allocatable_magnitude(operator_address, strategy_address)
    assert result == 1000000000000000000


def test_get_encumbered_magnitude(
    encumbered_operator_address, encumbered_strategy_address
):
    result = el_reader.get_encumbered_magnitude(
        encumbered_operator_address, encumbered_strategy_address
    )
    assert isinstance(result, int)


def test_get_max_magnitudes(
    max_magnitudes_operator_address, max_magnitudes_strategy_addresses
):
    result = el_reader.get_max_magnitudes(
        max_magnitudes_operator_address, max_magnitudes_strategy_addresses
    )
    assert result == [1000000000000000000, 1000000000000000000]


def test_get_allocation_info(allocation_operator_address, allocation_strategy_address):
    result = el_reader.get_allocation_info(
        allocation_operator_address, allocation_strategy_address
    )
    assert result == []


def test_get_operator_shares(
    operator_shares_operator_address, operator_shares_strategy_addresses
):
    result = el_reader.get_operator_shares(
        operator_shares_operator_address, operator_shares_strategy_addresses
    )
    assert result == [0, 0]


def test_get_operator_sets_for_operator(operator_sets_operator_address):
    result = el_reader.get_operator_sets_for_operator(operator_sets_operator_address)
    assert result == []


def test_get_allocation_delay(
    mocker, allocation_delay_operator_address, mock_allocation_manager
):
    mocker.patch.object(el_reader, "allocation_manager", mock_allocation_manager)
    result = el_reader.get_allocation_delay(allocation_delay_operator_address)
    assert result == 10


def test_get_registered_sets(registered_sets_operator_address):
    result = el_reader.get_registered_sets(registered_sets_operator_address)
    assert result == []


def test_calculate_operator_avs_registration_digestHash(
    operator_address, avs_address, salt, expiry
):
    result = el_reader.calculate_operator_avs_registration_digestHash(
        operator_address, avs_address, salt, expiry
    )
    assert isinstance(result, bytes)


def test_get_operators_for_operator_set(operator_set):
    result = el_reader.get_operators_for_operator_set(operator_set)
    assert result == []


def test_get_num_operators_for_operator_set(operator_set):
    result = el_reader.get_num_operators_for_operator_set(operator_set)
    assert result == 0


def test_get_strategies_for_operator_set(operator_set):
    result = el_reader.get_strategies_for_operator_set(operator_set)
    assert result == []


def test_is_operator_registered(operator_address):
    result = el_reader.is_operator_registered(operator_address)
    assert result == False


def test_get_staker_shares(staker_address):
    strategies, shares = el_reader.get_staker_shares(staker_address)
    assert strategies == []
    assert shares == []


def test_get_delegated_operator(staker_address, block_number):
    result = el_reader.get_delegated_operator(staker_address, block_number)
    assert str(result) == "0x0000000000000000000000000000000000000000"


def test_get_operator_details():
    operator = {
        "Address": "0x1111111111111111111111111111111111111111"
    }  # Use dictionary format
    result = el_reader.get_operator_details(operator)
    assert result == {
        "Address": "0x1111111111111111111111111111111111111111",
        "DelegationApproverAddress": False,
        "AllocationDelay": 0,
    }


def test_get_operator_shares_in_strategy(operator_address, strategy_address):
    result = el_reader.get_operator_shares_in_strategy(
        operator_address, strategy_address
    )
    assert result == 0


def test_calculate_delegation_approval_digest_hash(
    staker, operator, delegation_approver, approver_salt, expiry
):
    result = el_reader.calculate_delegation_approval_digest_hash(
        staker, operator, delegation_approver, approver_salt, expiry
    )
    assert isinstance(result, bytes)


def test_get_operator_shares(operator_address, strategy_addresses):
    result = el_reader.get_operator_shares(operator_address, strategy_addresses)
    assert result == [0, 0]


def test_get_operators_shares(operator_addresses, strategy_addresses):
    result = el_reader.get_operators_shares(operator_addresses, strategy_addresses)
    assert result == [[0, 0], [0, 0]]


def test_get_delegation_approver_salt_is_spent(delegation_approver, approver_salt):
    result = el_reader.get_delegation_approver_salt_is_spent(
        delegation_approver, approver_salt
    )
    assert result == False


def test_get_pending_withdrawal_status(withdrawal_root):
    result = el_reader.get_pending_withdrawal_status(withdrawal_root)
    assert result == False


def test_get_cumulative_withdrawals_queued(staker):
    result = el_reader.get_cumulative_withdrawals_queued(staker)
    assert result == 0


def test_can_call(account_address, appointee_address, target, selector):
    result = el_reader.can_call(account_address, appointee_address, target, selector)
    assert result == False


def test_list_appointees(account_address, target, selector):
    result = el_reader.list_appointees(account_address, target, selector)
    assert result == []


def test_list_appointee_permissions(account_address, appointee_address):
    targets, selectors = el_reader.list_appointee_permissions(
        account_address, appointee_address
    )
    assert targets == []
    assert selectors == []


def test_list_pending_admins(account_address):
    result = el_reader.list_pending_admins(account_address)
    assert result == []


def test_list_admins(account_address):
    result = el_reader.list_admins(account_address)
    assert result == ["0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"]


def test_is_pending_admin(account_address, pending_admin_address):
    result = el_reader.is_pending_admin(account_address, pending_admin_address)
    assert result == False


def test_is_admin(account_address, admin_address):
    result = el_reader.is_admin(account_address, admin_address)
    assert result == False


def test_get_distribution_roots_length():
    result = el_reader.get_distribution_roots_length()
    assert result == 0


def test_curr_rewards_calculation_end_timestamp():
    result = el_reader.curr_rewards_calculation_end_timestamp()
    assert result == 0


def test_get_current_claimable_distribution_root():
    result = el_reader.get_current_claimable_distribution_root()
    assert result == {
        "root": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        "startBlock": 0,
        "endBlock": 0,
        "totalClaimable": False,
    }


def test_get_root_index_from_hash(mocker):
    root_hash = "0xa3d1e5f47b6c9f8e2d3c4b5a6e7f8d9c0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d"

    # Mock the contract method to return a valid index instead of failing
    mock_reward_coordinator = mocker.MagicMock()
    mock_reward_coordinator.functions.getRootIndexFromHash.return_value.call.return_value = (
        5
    )
    mocker.patch.object(el_reader, "reward_cordinator", mock_reward_coordinator)

    result = el_reader.get_root_index_from_hash(root_hash)
    assert result == 5  # Ensure the mock is working


def test_get_cumulative_claimed(earner, token):
    result = el_reader.get_cumulative_claimed(earner, token)
    assert result == 0


def test_check_claim(claim):
    result = el_reader.check_claim(claim)
    assert result == False


def test_get_operator_avs_split(operator, avs):
    result = el_reader.get_operator_avs_split(operator, avs)
    assert result == 1000


def test_get_operator_pi_split(operator):
    result = el_reader.get_operator_pi_split(operator)
    assert result == 1000


def test_get_operator_set_split():
    operator = "0x1111111111111111111111111111111111111111"
    operator_set = {
        "avs": "0x2222222222222222222222222222222222222222",
        "id": 1,
    }  # Use lowercase keys

    result = el_reader.get_operator_set_split(operator, operator_set)
    assert result == 1000


def test_get_rewards_updater():
    result = el_reader.get_rewards_updater()
    assert str(result) == "0x18a0f92Ad9645385E8A8f3db7d0f6CF7aBBb0aD4"


def test_get_activation_delay():
    result = el_reader.GetActivationDelay()
    assert result == 0


def test_get_curr_rewards_calculation_end_timestamp():
    result = el_reader.get_curr_rewards_calculation_end_timestamp()
    assert result == 0


def test_get_default_operator_split_bips():
    result = el_reader.get_default_operator_split_bips()
    assert result == 1000


def test_get_claimer_for(earner):
    result = el_reader.get_claimer_for(earner)
    assert str(result) == "0x0000000000000000000000000000000000000000"


def test_get_submission_nonce(avs):
    result = el_reader.get_submission_nonce(avs)
    assert result == 0


def test_get_is_avs_rewards_submission_hash(avs, submission_hash):
    result = el_reader.get_is_avs_rewards_submission_hash(avs, submission_hash)
    assert result == False


def test_get_is_rewards_submission_for_all_hash(avs, submission_hash):
    result = el_reader.get_is_rewards_submission_for_all_hash(avs, submission_hash)
    assert result == False


def test_get_is_rewards_for_all_submitter(submitter):
    result = el_reader.get_is_rewards_for_all_submitter(submitter)
    assert result == False


def test_get_is_rewards_submission_for_all_earners_hash(avs, submission_hash):
    result = el_reader.get_is_rewards_submission_for_all_earners_hash(
        avs, submission_hash
    )
    assert result == False


def test_get_is_operator_directed_avs_rewards_submission_hash(avs, submission_hash):
    result = el_reader.get_is_operator_directed_avs_rewards_submission_hash(
        avs, submission_hash
    )
    assert result == False


def test_get_is_operator_directed_operator_set_rewards_submission_hash(
    avs, submission_hash
):
    result = el_reader.get_is_operator_directed_operator_set_rewards_submission_hash(
        avs, submission_hash
    )
    assert result == False


def test_calculate_operator_avs_registration_digest_hash(operator, avs, salt, expiry):
    result, error = el_reader.calculate_operator_avs_registration_digest_hash(
        operator, avs, salt, expiry
    )
    assert isinstance(result, bytes)


def test_get_calculation_interval_seconds():
    result, error = el_reader.get_calculation_interval_seconds()
    assert result == 604800


def test_get_max_rewards_duration():
    result, error = el_reader.get_max_rewards_duration()
    assert result == 6048000


def test_get_max_retroactive_length():
    result, error = el_reader.get_max_retroactive_length()
    assert result == 7776000


def test_get_max_future_length():
    result, error = el_reader.get_max_future_length()
    assert result == 2592000


def test_get_activation_delay():
    result, error = el_reader.get_activation_delay()
    assert result == 7200


def test_get_deallocation_delay():
    result, error = el_reader.get_deallocation_delay()
    assert result == 900


def test_get_allocation_configuration_delay():
    result, error = el_reader.get_allocation_configuration_delay()
    assert result == 1200


def test_get_num_operator_sets_for_operator(operator_address):
    result, error = el_reader.get_num_operator_sets_for_operator(operator_address)
    assert result == 0


def test_get_slashable_shares(operator_address, operator_set, strategies):
    result, error = el_reader.get_slashable_shares(
        operator_address, operator_set, strategies
    )
    assert result == None


def test_get_strategy_and_underlying_erc20_token(mocker, strategy_address):
    """Test get_strategy_and_underlying_erc20_token() with a mocked strategy contract."""
    mock_strategy_contract = MagicMock()
    mock_strategy_contract.functions.underlyingToken.return_value.call.return_value = (
        "0x2222222222222222222222222222222222222222"
    )
    mock_erc20_contract = MagicMock()
    mock_web3 = mocker.MagicMock()
    mock_web3.eth.contract.side_effect = lambda address, abi: (
        mock_strategy_contract if address == strategy_address else mock_erc20_contract
    )
    mocker.patch.object(el_reader, "eth_http_client", mock_web3)
    strategy_contract, erc20_contract, underlying_token_addr, error = (
        el_reader.get_strategy_and_underlying_erc20_token(strategy_address)
    )
    assert isinstance(
        underlying_token_addr, str
    ), f"\n❌ Expected underlying token address to be a string, but got {type(underlying_token_addr)}"
    assert (
        underlying_token_addr == "0x2222222222222222222222222222222222222222"
    ), f"\n❌ Unexpected underlying token address: {underlying_token_addr}"
