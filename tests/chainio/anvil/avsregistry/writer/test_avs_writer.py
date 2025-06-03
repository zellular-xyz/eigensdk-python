import pytest
from web3 import Web3
from tests.builder import clients, config
from tests.chainio.anvil.avsregistry.writer.utils import (
    register_as_operator,
    register_for_operator_sets,
)


@pytest.mark.order(3)
def test_update_stakes_of_entire_operator_set_for_quorums():
    try:
        register_as_operator()
        register_for_operator_sets()
    except AssertionError:  # FIXME simplify flow
        pass

    operator_addr = Web3.to_checksum_address(config["operator_address_2"])
    operators_per_quorum = [[operator_addr]]
    quorum_numbers = [0]
    receipt = clients.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
        operators_per_quorum, quorum_numbers
    )
    assert receipt is not None
    print(f"Updated stakes with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(4)
def test_update_socket():
    try:
        register_as_operator()
        register_for_operator_sets()
    except AssertionError:  # FIXME simplify code flow
        pass
    new_socket = "192.168.1.100:9000"
    receipt = clients.avs_registry_writer.update_socket(new_socket)
    assert receipt is not None
    print(f"Updated socket with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(5)
def test_set_avs():
    avs_address = Web3.to_checksum_address(config["service_manager_address"])
    receipt = clients.avs_registry_writer.set_avs(avs_address)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set AVS with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(6)
def test_update_stakes_of_operator_subset_for_all_quorums():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operators = [operator_addr]
    receipt = clients.avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(
        operators
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated stakes for operator subset with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(7)
def test_set_rewards_initiator():
    rewards_initiator_addr = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_rewards_initiator(rewards_initiator_addr)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set rewards initiator with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(8)
def test_set_minimum_stake_for_quorum():
    quorum_number = 0
    minimum_stake = 1000000
    receipt = clients.avs_registry_writer.set_minimum_stake_for_quorum(quorum_number, minimum_stake)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set minimum stake for quorum with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(9)
def test_create_total_delegated_stake_quorum():

    operator_set_param_dict = {
        "MaxOperatorCount": 10,
        "KickBIPsOfOperatorStake": 10000,
        "KickBIPsOfTotalStake": 2000,
    }

    operator_set_params = (
        operator_set_param_dict["MaxOperatorCount"],
        operator_set_param_dict["KickBIPsOfOperatorStake"],
        operator_set_param_dict["KickBIPsOfTotalStake"],
    )

    minimum_stake_required = 1000000
    strategy_addr = Web3.to_checksum_address(config["strategy_addr"])
    strategy_params = [(strategy_addr, 10000)]
    receipt = clients.avs_registry_writer.create_total_delegated_stake_quorum(
        operator_set_params, minimum_stake_required, strategy_params
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Created total delegated stake quorum with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(10)
def test_set_operator_set_params():
    quorum_number = 0
    operator_set_params = {
        "maxOperatorCount": 10,
        "kickBIPsOfOperatorStake": 10000,
        "kickBIPsOfTotalStake": 2000,
    }
    receipt = clients.avs_registry_writer.set_operator_set_params(
        quorum_number, operator_set_params
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set operator set params with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(11)
def test_set_churn_approver():
    churn_approver_address = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_churn_approver(churn_approver_address)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set churn approver with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(12)
def test_set_ejector():
    ejector_address = Web3.to_checksum_address(config["operator_address"])
    receipt = clients.avs_registry_writer.set_ejector(ejector_address)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set ejector with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(13)
def test_modify_strategy_params():
    quorum_number = 0
    strategy_indices = [0]
    multipliers = [8000]
    receipt = clients.avs_registry_writer.modify_strategy_params(
        quorum_number, strategy_indices, multipliers
    )
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Modified strategy parameters with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(14)
def test_set_ejection_cooldown():
    ejection_cooldown = 100
    receipt = clients.avs_registry_writer.set_ejection_cooldown(ejection_cooldown)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Set ejection cooldown with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(15)
def test_update_avs_metadata_uri():
    metadata_uri = "https://example.com/avs-metadata-updated"
    receipt = clients.avs_registry_writer.update_avs_metadata_uri(metadata_uri)
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Updated AVS metadata URI with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(16)
def test_create_avs_rewards_submission():
    strategies = clients.avs_registry_reader.strategy_params_by_index(quorum_number=0, index=0)
    strategy_addr = strategies[0]
    duration = clients.el_reader.get_calculation_interval_seconds()
    token = clients.el_reader.get_strategy_and_underlying_token(strategy_addr)[1]

    strategy_and_multiplier = {"strategy": Web3.to_checksum_address(strategy_addr), "multiplier": 1}

    latest_block = clients.eth_http_client.eth.get_block("latest")
    block_time = latest_block["timestamp"]
    start_timestamp = ((block_time // duration) + 1) * duration
    rewards_submission = {
        "strategiesAndMultipliers": [strategy_and_multiplier],
        "token": Web3.to_checksum_address(token),
        "amount": 1000,
        "startTimestamp": start_timestamp,
        "duration": duration,
    }

    receipt = clients.avs_registry_writer.create_avs_rewards_submission([rewards_submission])
    assert receipt is not None
    assert receipt["status"] == 1
    print(f"Created AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(17)
def test_create_slashable_stake_quorum():
    operator_set_params = (
        10,  # MaxOperatorCount
        10000,  # KickBIPsOfOperatorStake
        2000,  # KickBIPsOfTotalStake
    )
    minimum_stake_required = 0
    strategies = clients.avs_registry_reader.strategy_params_by_index(quorum_number=0, index=0)
    strategy_addr = strategies[0]
    strategy_param = {"strategy": strategy_addr, "multiplier": 10000}
    look_ahead_period = 50400  # ~1 week in blocks (assuming ~12s block time)
    receipt = clients.avs_registry_writer.create_slashable_stake_quorum(
        operator_set_params, minimum_stake_required, [strategy_param], look_ahead_period
    )
    assert receipt is not None
    # assert receipt["status"] == 1
    print(f"Created slashable stake quorum with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(18)
def test_set_slashable_stake_lookahead():
    quorum_number = 0
    look_ahead_period = 50400  # ~1 week in blocks (assuming ~12s block time)
    receipt = clients.avs_registry_writer.set_slashable_stake_lookahead(
        quorum_number, look_ahead_period
    )
    assert receipt is not None
    if receipt["status"] == 1:
        print(f"Set slashable stake lookahead with tx hash: {receipt['transactionHash'].hex()}")
    else:
        print("Quorum is not Slashable Stake Quorum")


@pytest.mark.order(19)
def test_add_strategies():
    strategies = clients.avs_registry_reader.strategy_params_by_index(quorum_number=0, index=0)
    strategy_addr = strategies[0]
    strategy_params = {"strategy": strategy_addr, "multiplier": 10000}
    receipt = clients.avs_registry_writer.add_strategies(
        quorum_number=0, strategy_params=[strategy_params]
    )
    assert receipt is not None
    # assert receipt["status"] == 1
    print(f"Added strategies with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(20)
def test_eject_operator():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    quorum_numbers = [0]  # Eject from quorum 0
    receipt = clients.avs_registry_writer.eject_operator(
        operator_address=operator_addr, quorum_numbers=quorum_numbers
    )
    assert receipt is not None
    # assert receipt["status"] == 1
    print(f"Ejected operator with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(21)
def test_remove_strategies():
    quorum_number = 0
    indices_to_remove = [1]
    receipt = clients.avs_registry_writer.remove_strategies(quorum_number, indices_to_remove)
    assert receipt is not None
    # assert receipt["status"] == 1
    print(f"Removed strategies with tx hash: {receipt['transactionHash'].hex()}")


@pytest.mark.order(22)
def test_create_operator_directed_avs_rewards_submission():
    strategies = clients.avs_registry_reader.strategy_params_by_index(quorum_number=0, index=0)
    strategy_addr = strategies[0]
    duration = clients.el_reader.get_calculation_interval_seconds()
    token = clients.el_reader.get_strategy_and_underlying_token(strategy_addr)[1]
    latest_block = clients.eth_http_client.eth.get_block("latest")
    block_time = latest_block["timestamp"]
    start_timestamp = ((block_time // duration) + 1) * duration
    strategy_and_multiplier = {"strategy": Web3.to_checksum_address(strategy_addr), "multiplier": 1}
    operator_rewards = [(Web3.to_checksum_address(config["operator_address"]), 1000)]

    rewards_submission = {
        "strategiesAndMultipliers": [strategy_and_multiplier],
        "token": Web3.to_checksum_address(token),
        "operatorRewards": operator_rewards,
        "startTimestamp": start_timestamp,
        "duration": duration,
        "description": "Some Description",
    }

    receipt = clients.avs_registry_writer.create_operator_directed_avs_rewards_submission(
        [rewards_submission]
    )
    assert receipt is not None
    # assert receipt["status"] == 1
    print(f"Created AVS rewards submission with tx hash: {receipt['transactionHash'].hex()}")
