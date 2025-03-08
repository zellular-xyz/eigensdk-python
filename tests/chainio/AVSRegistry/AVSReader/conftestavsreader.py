import pytest
from unittest.mock import Mock
from AvsRegistryReader import AvsRegistryReader

@pytest.fixture
def mock_registry_coordinator():
    return Mock()

@pytest.fixture
def avs_registry_reader(mock_registry_coordinator):
    return AvsRegistryReader(
        registry_coordinator_addr="0xRegistryCoordinatorAddr",
        registry_coordinator=mock_registry_coordinator,
        bls_apk_registry_addr="0xBlsApkRegistryAddr",
        bls_apk_registry=Mock(),
        operator_state_retriever=Mock(),
        stake_registry=Mock(),
        logger=Mock(),
        eth_http_client=Mock()
    )

def test_get_quorum_count(avs_registry_reader):
    # Successful quorum count retrieval
    avs_registry_reader.registry_coordinator.functions.quorumCount.return_value.call.return_value = 5
    result, error = avs_registry_reader.get_quorum_count()
    assert result == 5
    assert error is None

    # RegistryCoordinator contract is None scenario
    avs_registry_reader.registry_coordinator = None
    result, error = avs_registry_reader.get_quorum_count()

    assert result == 0
    assert isinstance(error, ValueError)
    assert str(error) == "RegistryCoordinator contract not provided"

    # Exception thrown from contract call
    avs_registry_reader.registry_coordinator = Mock()
    avs_registry_reader.registry_coordinator.functions.quorumCount.return_value.call.side_effect = Exception("Contract call failed")

    result, error = avs_registry_reader.get_quorum_count()

    assert result == 0
    assert isinstance(error, Exception)
    assert str(error) == "Contract logic error or external failure"


def test_get_operators_stake_in_quorums_at_current_block(avs_registry_reader, mocker):
    quorum_numbers = mocker.Mock()
    expected_result = [[OperatorStateRetrieverOperator(operator="0xOperator1", stake=100)]]

    # Successful case
    mocker.patch.object(
        avs_registry_reader,
        "get_operators_stake_in_quorums_at_block",
        return_value=expected_result
    )
    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_current_block({}, quorum_numbers)

    assert error is None
    assert result == expected_result
    avs_registry_reader.get_operators_stake_in_quorums_at_block.assert_called_with(
        {}, quorum_numbers,  avs_registry_reader.eth_http_client.eth.block_number
    )

    # Current block number too large scenario
    avs_registry_reader.eth_http_client.eth.block_number = 2**32
    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_current_block({}, quorum_numbers)
    assert result is None
    assert isinstance(error, ValueError)
    assert str(error) == "Current block number is too large to be converted to uint32"

    # Exception scenario
    avs_registry_reader.eth_http_client.eth.block_number = 123456
    avs_registry_reader.get_operators_stake_in_quorums_at_block.side_effect = Exception("Contract call failed")
    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_current_block({}, quorum_numbers)

    assert result is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"

def test_get_operators_stake_in_quorums_at_block(avs_registry_reader, mocker):
    quorum_numbers = mocker.Mock()
    block_number = 123456

    mock_operator_stakes = [
        [OperatorStateRetrieverOperator(operator="0xOperator1", stake=100)],
        [OperatorStateRetrieverOperator(operator="0xOperator2", stake=200)]
    ]

    # --- Successful case ---
    avs_registry_reader.operator_state_retriever.functions.getOperatorState.return_value.call.return_value = mock_operator_stakes

    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_block({}, quorum_numbers, block_number)

    assert error is None
    assert result == mock_operator_stakes
    avs_registry_reader.operator_state_retriever.functions.getOperatorState.assert_called_with(
        avs_registry_reader.registry_coordinator_addr,
        quorum_numbers.underlying_type(),
        block_number
    )

    # Contract not provided scenario
    avs_registry_reader.operator_state_retriever = None
    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_block({}, quorum_numbers, block_number)

    assert result is None
    assert isinstance(error, ValueError)
    assert str(error) == "OperatorStateRetriever contract not provided"

    # Exception scenario (contract call failure)
    avs_registry_reader.operator_state_retriever = Mock()
    avs_registry_reader.operator_state_retriever.functions.getOperatorState.side_effect = Exception("Contract call failed")

    result, error = avs_registry_reader.get_operators_stake_in_quorums_at_block({}, quorum_numbers, block_number)

    assert result is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_operator_addrs_in_quorums_at_current_block(avs_registry_reader, mocker):
    quorum_numbers = mocker.Mock()
    quorum_numbers.underlying_type.return_value = [1, 2]

    mock_operator_stakes = [
        [{"operator": "0xOperatorA"}, {"operator": "0xOperatorB"}],
        [{"operator": "0xOperatorC"}]
    ]

    # Successful case
    avs_registry_reader.operator_state_retriever.functions.getOperatorState.return_value.call.return_value = mock_operator_stakes = [
        [{"operator": "0xOperator1"}, {"operator": "0xOperator2"}],
        [{"operator": "0xOperator3"}]
    ]

    result, error = avs_registry_reader.get_operator_addrs_in_quorums_at_current_block({}, quorum_numbers)

    assert error is None
    assert result == [["0xOperator1", "0xOperator2"], ["0xOperator3"]]

    avs_registry_reader.operator_state_retriever.functions.getOperatorState.assert_called_with(
        avs_registry_reader.registry_coordinator_addr,
        quorum_numbers.underlying_type(),
        avs_registry_reader.eth_http_client.eth.block_number
    )

    # OperatorStateRetriever contract not provided scenario
    avs_registry_reader.operator_state_retriever = None

    result, error = avs_registry_reader.get_operator_addrs_in_quorums_at_current_block({}, quorum_numbers)

    assert result is None
    assert isinstance(error, ValueError)
    assert str(error) == "OperatorStateRetriever contract not provided"

    # Current block number too large scenario
    avs_registry_reader.operator_state_retriever = Mock()
    avs_registry_reader.eth_http_client.eth.block_number = 2**32

    result, error = avs_registry_reader.get_operator_addrs_in_quorums_at_current_block({}, quorum_numbers)

    assert result is None
    assert isinstance(error, ValueError)
    assert str(error) == "Current block number is too large to be converted to uint32"

    # Exception raised during contract call scenario
    avs_registry_reader.eth_http_client.eth.block_number = 1000
    avs_registry_reader.operator_state_retriever.functions.getOperatorState.return_value.call.side_effect = Exception("Contract call failed")

    result, error = avs_registry_reader.get_operator_addrs_in_quorums_at_current_block({}, quorum_numbers)

    assert result is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


@patch('AvsRegistryReader.bitmap_to_quorum_ids', return_value=[1, 2])
def test_get_operators_stake_in_quorums_of_operator_at_block(mock_bitmap_to_quorum_ids, avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    block_number = 1000

    mock_quorum_bitmap = 0b11  # represents quorum IDs [1, 2]
    mock_operator_stakes = [
        [OperatorStateRetrieverOperator(operator="0xOperator1", stake=150)],
        [OperatorStateRetrieverOperator(operator="0xOperator2", stake=200)]
    ]

    # Successful scenario
    avs_registry_reader.operator_state_retriever.functions.getOperatorState0.return_value.call.return_value = (
        mock_quorum_bitmap,
        mock_operator_stakes
    )

    quorums, operator_stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        call_options, operator_id, block_number
    )

    assert error is None
    assert quorums == [1, 2]
    assert operator_stakes == mock_operator_stakes
    avs_registry_reader.operator_state_retriever.functions.getOperatorState0.assert_called_with(
        avs_registry_reader.registry_coordinator_addr,
        operator_id,
        block_number
    )
    mock_bitmap_to_quorum_ids.assert_called_with(mock_quorum_bitmap)

    # Contract missing scenario
    avs_registry_reader.operator_state_retriever = None

    quorums, operator_stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        call_options, operator_id, block_number
    )

    assert quorums is None
    assert operator_stakes is None
    assert isinstance(error, ValueError)
    assert str(error) == "OperatorStateRetriever contract not provided"

    # Exception scenario (contract call fails)
    avs_registry_reader.operator_state_retriever = Mock()
    avs_registry_reader.operator_state_retriever.functions.getOperatorState0.return_value.call.side_effect = Exception("Contract call failed")

    quorums, operator_stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        call_options, operator_id, block_number
    )

    assert quorums is None
    assert operator_stakes is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_operators_stake_in_quorums_of_operator_at_current_block(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'

    mock_quorums = [1, 2]
    mock_operator_stakes = [
        [OperatorStateRetrieverOperator(operator="0xOperator1", stake=150)],
        [OperatorStateRetrieverOperator(operator="0xOperator2", stake=250)]
    ]

    # Successful scenario
    avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block.return_value = (mock_quorums, mock_operator_stakes, None)

    quorums, stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(call_options, operator_id)

    assert error is None
    assert quorums == mock_quorums
    assert stakes == mock_operator_stakes
    avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block.assert_called_with(
        {"block_number": 123456}, operator_id, 123456
    )

    # Current block number too large scenario
    avs_registry_reader.eth_http_client.eth.block_number = 2**32

    quorums, stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(call_options, operator_id)

    assert quorums is None
    assert stakes is None
    assert isinstance(error, ValueError)
    assert str(error) == "Current block number is too large to be converted to uint32"

    # Exception scenario during underlying call
    avs_registry_reader.eth_http_client.eth.block_number = 123456
    avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block.side_effect = Exception("Contract call failed")

    quorums, stakes, error = avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(call_options, operator_id)

    assert quorums is None
    assert stakes is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


@patch('AvsRegistryReader.bitmap_to_quorum_ids', return_value=[1, 2])
def test_get_operator_stake_in_quorums_of_operator_at_current_block(mock_bitmap_to_quorum_ids, avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'

    # Mock returned values
    mock_quorum_bitmap = 0b11  # quorum IDs [1, 2]
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = mock_quorum_bitmap
    avs_registry_reader.stake_registry.functions.getCurrentStake.side_effect = [150, 250]

    # Successful scenario
    quorum_stakes, error = avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options, operator_id
    )

    assert error is None
    assert quorum_stakes == {1: 150, 2: 250}
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_with(
        operator_id
    )
    avs_registry_reader.stake_registry.functions.getCurrentStake.assert_any_call(operator_id, 1)
    avs_registry_reader.stake_registry.functions.getCurrentStake.assert_any_call(operator_id, 2)

    # RegistryCoordinator not provided scenario
    avs_registry_reader.registry_coordinator = None
    quorum_stakes, error = avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options, operator_id
    )
    assert quorum_stakes is None
    assert isinstance(error, ValueError)
    assert str(error) == "RegistryCoordinator contract not provided"

    # StakeRegistry not provided scenario
    avs_registry_reader.registry_coordinator = Mock()
    avs_registry_reader.stake_registry = None
    quorum_stakes, error = avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options, operator_id
    )
    assert quorum_stakes is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.side_effect = Exception("Contract call failed")

    quorum_stakes, error = avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
        call_options, operator_id
    )
    assert quorum_stakes is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_weight_of_operator_for_quorum(avs_registry_reader):
    quorum_number = 1
    operator_addr = "0xOperatorAddr"
    call_options = {}

    # Successful case
    avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.return_value = 500

    stake, error = avs_registry_reader.weight_of_operator_for_quorum(call_options, quorum_number, operator_addr)

    assert error is None
    assert stake == 500
    avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.assert_called_with(
        quorum_number, operator_addr
    )

    # StakeRegistry contract missing scenario
    avs_registry_reader.stake_registry = None

    stake, error = avs_registry_reader.weight_of_operator_for_quorum(call_options, quorum_number, operator_addr)

    assert stake is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario (contract call failure)
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.side_effect = Exception("Contract call failed")

    stake, error = avs_registry_reader.weight_of_operator_for_quorum(call_options, quorum_number, operator_addr)

    assert stake is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_strategy_params_length(avs_registry_reader):
    quorum_number = 3
    call_options = {}

    # Successful scenario
    avs_registry_reader.stake_registry.functions.strategyParamsLength.return_value.call.return_value = 10

    length, error = avs_registry_reader.strategy_params_length(call_options={}, quorum_number=quorum_number)

    assert error is None
    assert length == 10
    avs_registry_reader.stake_registry.functions.strategyParamsLength.assert_called_once_with(quorum_number)

    # Contract not provided scenario
    avs_registry_reader.stake_registry = None

    length, error = avs_registry_reader.strategy_params_length(call_options={}, quorum_number=quorum_number)

    assert length is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.strategyParamsLength.return_value.call.side_effect = Exception("Contract call failed")

    length, error = avs_registry_reader.strategy_params_length(call_options={}, quorum_number=quorum_number)

    assert length is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"

def test_strategy_params_by_index(avs_registry_reader):
    quorum_number = 1
    index = 0
    call_options = {}

    mock_param = {
        "param1": 100,
        "param2": "0xSomeAddress"
    }

    # Successful scenario
    avs_registry_reader.stake_registry.functions.strategyParamsByIndex.return_value.call.return_value = mock_param = {
        "param1": 123,
        "param2": "0xParamAddress"
    }

    param, error = avs_registry_reader.strategy_params_by_index(call_options, quorum_number, index)

    assert error is None
    assert param == mock_param
    avs_registry_reader.stake_registry.functions.strategyParamsByIndex.assert_called_with(
        quorum_number, index
    )

    # Contract missing scenario
    avs_registry_reader.stake_registry = None

    param, error = avs_registry_reader.strategy_params_by_index(call_options, quorum_number, index)

    assert param is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.strategyParamsByIndex.return_value.call.side_effect = Exception("Contract call failed")

    param, error = avs_registry_reader.strategy_params_by_index(call_options, quorum_number, index)

    assert param is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"

def test_get_stake_history_length(avs_registry_reader):
    call_options = {}
    operator_id = b'\x12\x34\x56'
    quorum_number = 2

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.return_value = 15

    length, error = avs_registry_reader.get_stake_history_length(call_options, operator_id, quorum_number)

    assert error is None
    assert length == 15
    avs_registry_reader.stake_registry.functions.getStakeHistoryLength.assert_called_with(
        operator_id, quorum_number
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    length, error = avs_registry_reader.get_stake_history_length(call_options, operator_id, quorum_number)

    assert length is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.side_effect = Exception("Contract call failed")

    length, error = avs_registry_reader.get_stake_history_length(call_options, operator_id, quorum_number)

    assert length is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_stake_history(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    quorum_number = 1

    mock_stake_history = [
        {"stake": 100, "blockNumber": 123},
        {"stake": 200, "blockNumber": 456}
    ]

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeHistory.return_value.call.return_value = mock_stake_history

    stake_history, error = avs_registry_reader.get_stake_history(call_options={}, operator_id=operator_id, quorum_number=quorum_number)

    assert error is None
    assert stake_history == mock_stake_history
    avs_registry_reader.stake_registry.functions.getStakeHistory.assert_called_with(operator_id, quorum_number)

    # Contract not provided scenario
    avs_registry_reader.stake_registry = None

    stake_history, error = avs_registry_reader.get_stake_history(call_options={}, operator_id=operator_id, quorum_number=quorum_number)

    assert stake_history is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeHistory.return_value.call.side_effect = Exception("Contract call failed")

    stake_history, error = avs_registry_reader.get_stake_history(call_options={}, operator_id=operator_id, quorum_number=quorum_number)

    assert stake_history is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_latest_stake_update(avs_registry_reader):
    operator_id = b'\x01\x23\x45'
    quorum_number = 1
    call_options = {}

    mock_stake_update = {
        "stake": 300,
        "blockNumber": 123456
    }

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getLatestStakeUpdate.return_value.call.return_value = mock_stake_update

    stake_update, error = avs_registry_reader.get_latest_stake_update(call_options, operator_id, quorum_number)

    assert error is None
    assert stake_update == mock_stake_update
    avs_registry_reader.stake_registry.functions.getLatestStakeUpdate.assert_called_with(
        operator_id, quorum_number
    )

    # StakeRegistry contract missing scenario
    avs_registry_reader.stake_registry = None

    stake_update, error = avs_registry_reader.get_latest_stake_update(call_options, operator_id, quorum_number)

    assert stake_update is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getLatestStakeUpdate.return_value.call.side_effect = Exception("Contract call failed")

    stake_update, error = avs_registry_reader.get_latest_stake_update(call_options, operator_id, quorum_number)

    assert stake_update is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_stake_update_at_index(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    quorum_number = 2
    index = 0

    mock_stake_update = {
        "stake": 500,
        "blockNumber": 654321
    }

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeUpdateAtIndex.return_value.call.return_value = mock_stake_update

    stake_update, error = avs_registry_reader.get_stake_update_at_index(call_options, operator_id, quorum_number, index)

    assert error is None
    assert stake_update == mock_stake_update
    avs_registry_reader.stake_registry.functions.getStakeUpdateAtIndex.assert_called_with(
        quorum_number, operator_id, index
    )

    # StakeRegistry contract missing scenario
    avs_registry_reader.stake_registry = None

    stake_update, error = avs_registry_reader.get_stake_update_at_index(call_options, operator_id, quorum_number, index)

    assert stake_update is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeUpdateAtIndex.return_value.call.side_effect = Exception("Contract call failed")

    stake_update, error = avs_registry_reader.get_stake_update_at_index(call_options, operator_id, quorum_number, index)

    assert stake_update is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"

def test_get_stake_at_block_number(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    quorum_number = 2
    block_number = 5000

    mock_stake = 750

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.return_value = mock_stake

    stake, error = avs_registry_reader.get_stake_at_block_number(call_options, operator_id, quorum_number, block_number)

    assert error is None
    assert stake == mock_stake
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.assert_called_with(
        operator_id, quorum_number, block_number
    )

    # StakeRegistry contract missing scenario
    avs_registry_reader.stake_registry = None

    stake, error = avs_registry_reader.get_stake_at_block_number(call_options, operator_id, quorum_number, block_number)

    assert stake is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.side_effect = Exception("Contract call failed")

    stake, error = avs_registry_reader.get_stake_at_block_number(call_options, operator_id, quorum_number, block_number)

    assert stake is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_stake_update_index_at_block_number(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    quorum_number = 1
    block_number = 98765

    mock_index = 4

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.return_value = mock_index

    index, error = avs_registry_reader.get_stake_update_index_at_block_number(
        call_options, operator_id, quorum_number, block_number
    )

    assert error is None
    assert index == mock_index
    avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.assert_called_with(
        operator_id, quorum_number, block_number
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    index, error = avs_registry_reader.get_stake_update_index_at_block_number(
        call_options, operator_id, quorum_number, block_number
    )

    assert index is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.side_effect = Exception("Contract call failed")

    index, error = avs_registry_reader.get_stake_update_index_at_block_number(
        call_options, operator_id, quorum_number, block_number
    )

    assert index is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_stake_at_block_number_and_index(avs_registry_reader):
    call_options = {}
    operator_id = b'\x01\x23\x45'
    quorum_number = 3
    block_number = 88888
    index = 5

    mock_stake_amount = 1200

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.return_value.call.return_value = mock_stake_amount

    stake, error = avs_registry_reader.get_stake_at_block_number_and_index(
        call_options, operator_id, quorum_number, block_number, index
    )

    assert error is None
    assert stake == mock_stake_amount
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.assert_called_with(
        quorum_number, block_number, operator_id, index
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    stake, error = avs_registry_reader.get_stake_at_block_number_and_index(
        call_options, operator_id, quorum_number, block_number, index
    )

    assert stake is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.return_value.call.side_effect = Exception("Contract call failed")

    stake, error = avs_registry_reader.get_stake_at_block_number_and_index(
        call_options, operator_id, quorum_number, block_number, index
    )

    assert stake is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_total_stake_history_length(avs_registry_reader):
    call_options = {}
    quorum_number = 2

    mock_length = 25

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.return_value = mock_length

    length, error = avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

    assert error is None
    assert length == mock_length
    avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.assert_called_with(
        quorum_number
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    length, error = avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

    assert length is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.side_effect = Exception("Contract call failed")

    length, error = avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

    assert length is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_check_signatures_indices(avs_registry_reader, mocker):
    call_options = {}
    reference_block_number = 123456
    quorum_numbers = mocker.Mock()
    quorum_numbers.underlying_type.return_value = [1, 2]
    non_signer_operator_ids = [b'\x01\x23', b'\x45\x67']

    mock_indices = {
        "indices": [0, 1],
        "missing_indices": [2, 3]
    }

    # Successful scenario
    avs_registry_reader.operator_state_retriever.functions.getCheckSignaturesIndices.return_value.call.return_value = mock_indices

    indices, error = avs_registry_reader.get_check_signatures_indices(
        call_options, reference_block_number, quorum_numbers, non_signer_operator_ids
    )

    assert error is None
    assert indices == mock_indices
    avs_registry_reader.operator_state_retriever.functions.getCheckSignaturesIndices.assert_called_with(
        avs_registry_reader.registry_coordinator_addr,
        reference_block_number,
        quorum_numbers.underlying_type(),
        non_signer_operator_ids
    )

    # OperatorStateRetriever missing scenario
    avs_registry_reader.operator_state_retriever = None

    indices, error = avs_registry_reader.get_check_signatures_indices(
        call_options, reference_block_number, quorum_numbers, non_signer_operator_ids
    )

    assert indices is None
    assert isinstance(error, ValueError)
    assert str(error) == "OperatorStateRetriever contract not provided"

    # Exception during contract call
    avs_registry_reader.operator_state_retriever = Mock()
    avs_registry_reader.operator_state_retriever.functions.getCheckSignaturesIndices.return_value.call.side_effect = Exception("Contract call failed")

    indices, error = avs_registry_reader.get_check_signatures_indices(
        call_options, reference_block_number, quorum_numbers, non_signer_operator_ids
    )

    assert indices is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_current_total_stake(avs_registry_reader):
    call_options = {}
    quorum_number = 2
    mock_stake_amount = 10000

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.return_value = mock_stake_amount

    stake, error = avs_registry_reader.get_current_total_stake(call_options, quorum_number)

    assert error is None
    assert stake == mock_stake_amount
    avs_registry_reader.stake_registry.functions.getCurrentTotalStake.assert_called_with(quorum_number)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    stake, error = avs_registry_reader.get_current_total_stake(call_options, quorum_number)

    assert stake is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.side_effect = Exception("Contract call failed")

    stake, error = avs_registry_reader.get_current_total_stake(call_options, quorum_number)

    assert stake is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_total_stake_update_at_index(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    index = 3

    mock_stake_update = {
        "stake": 1500,
        "blockNumber": 123789
    }

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getTotalStakeUpdateAtIndex.return_value.call.return_value = mock_stake_update

    stake_update, error = avs_registry_reader.get_total_stake_update_at_index(call_options, quorum_number, index)

    assert error is None
    assert stake_update == mock_stake_update
    avs_registry_reader.stake_registry.functions.getTotalStakeUpdateAtIndex.assert_called_with(
        quorum_number, index
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    stake_update, error = avs_registry_reader.get_total_stake_update_at_index(call_options, quorum_number, index)

    assert stake_update is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception scenario during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getTotalStakeUpdateAtIndex.return_value.call.side_effect = Exception("Contract call failed")

    stake_update, error = avs_registry_reader.get_total_stake_update_at_index(call_options, quorum_number, index)

    assert stake_update is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_total_stake_indices_at_block_number(avs_registry_reader):
    call_options = {}
    quorum_numbers = Mock()
    quorum_numbers.underlying_type.return_value = [1, 2, 3]
    block_number = 50000

    mock_indices = [3, 7, 12]

    # Successful scenario
    avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.return_value.call.return_value = mock_indices

    indices, error = avs_registry_reader.get_total_stake_indices_at_block_number(
        call_options, quorum_numbers, block_number
    )

    assert error is None
    assert indices == mock_indices
    avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.assert_called_with(
        block_number, quorum_numbers.underlying_type()
    )

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    indices, error = avs_registry_reader.get_total_stake_indices_at_block_number(
        call_options, quorum_numbers, block_number
    )

    assert indices is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.return_value.call.side_effect = Exception("Contract call failed")

    indices, error = avs_registry_reader.get_total_stake_indices_at_block_number(
        call_options, quorum_numbers, block_number
    )

    assert indices is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_minimum_stake_for_quorum(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    mock_stake = 1000

    # Successful scenario
    avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.return_value = mock_stake

    stake, error = avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

    assert error is None
    assert stake == mock_stake
    avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.assert_called_with(quorum_number)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    stake, error = avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

    assert stake is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.side_effect = Exception("Contract call failed")

    stake, error = avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

    assert stake is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_strategy_params_at_index(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    index = 0
    mock_params = {"param1": "value1", "param2": "value2"}

    # Successful scenario
    avs_registry_reader.stake_registry.functions.strategyParams.return_value.call.return_value = mock_params

    params, error = avs_registry_reader.get_strategy_params_at_index(call_options, quorum_number, index)

    assert error is None
    assert params == mock_params
    avs_registry_reader.stake_registry.functions.strategyParams.assert_called_with(quorum_number, index)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    params, error = avs_registry_reader.get_strategy_params_at_index(call_options, quorum_number, index)

    assert params is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.strategyParams.return_value.call.side_effect = Exception("Contract call failed")

    params, error = avs_registry_reader.get_strategy_params_at_index(call_options, quorum_number, index)

    assert params is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"

def test_get_strategy_per_quorum_at_index(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    index = 0
    mock_strategy = "0xStrategyAddress"

    # Successful scenario
    avs_registry_reader.stake_registry.functions.strategiesPerQuorum.return_value.call.return_value = mock_strategy

    strategy, error = avs_registry_reader.get_strategy_per_quorum_at_index(call_options, quorum_number, index)

    assert error is None
    assert strategy == mock_strategy
    avs_registry_reader.stake_registry.functions.strategiesPerQuorum.assert_called_with(quorum_number, index)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    strategy, error = avs_registry_reader.get_strategy_per_quorum_at_index(call_options, quorum_number, index)

    assert strategy is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Exception during contract call
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.strategiesPerQuorum.return_value.call.side_effect = Exception("Contract call failed")

    strategy, error = avs_registry_reader.get_strategy_per_quorum_at_index(call_options, quorum_number, index)

    assert strategy is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_restakeable_strategies(avs_registry_reader, mocker):
    call_options = {}

    mock_strategies = ["0xStrategy1", "0xStrategy2", "0xStrategy1"]
    deduplicated_strategies = ["0xStrategy1", "0xStrategy2"]

    # Mock the remove_duplicate_strategies function
    mocker.patch("AvsRegistryReader.remove_duplicate_strategies", return_value=deduplicated_strategies)

    # Successful scenario
    avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.return_value = mock_strategies

    strategies, error = avs_registry_reader.get_restakeable_strategies(call_options)

    assert error is None
    assert strategies == deduplicated_strategies
    avs_registry_reader.service_manager.functions.getRestakeableStrategies.assert_called_with()

    # ServiceManager missing scenario
    avs_registry_reader.service_manager = None

    strategies, error = avs_registry_reader.get_restakeable_strategies(call_options)

    assert strategies is None
    assert isinstance(error, ValueError)
    assert str(error) == "ServiceManager contract not provided"

    # Contract call failure
    avs_registry_reader.service_manager = Mock()
    avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.side_effect = Exception("Contract call failed")

    strategies, error = avs_registry_reader.get_restakeable_strategies(call_options)

    assert strategies is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_operator_restaked_strategies(avs_registry_reader, mocker):
    call_options = {}
    operator = "0xOperatorAddress"

    mock_strategies = ["0xStrategy1", "0xStrategy2", "0xStrategy1"]
    deduplicated_strategies = ["0xStrategy1", "0xStrategy2"]

    # Mock the remove_duplicate_strategies function
    mocker.patch("AvsRegistryReader.remove_duplicate_strategies", return_value=deduplicated_strategies)

    # Successful scenario
    avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.return_value = mock_strategies

    strategies, error = avs_registry_reader.get_operator_restaked_strategies(call_options, operator)

    assert error is None
    assert strategies == deduplicated_strategies
    avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.assert_called_with(operator)

    # ServiceManager missing scenario
    avs_registry_reader.service_manager = None

    strategies, error = avs_registry_reader.get_operator_restaked_strategies(call_options, operator)

    assert strategies is None
    assert isinstance(error, ValueError)
    assert str(error) == "ServiceManager contract not provided"

    # Contract call failure
    avs_registry_reader.service_manager = Mock()
    avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.side_effect = Exception("Contract call failed")

    strategies, error = avs_registry_reader.get_operator_restaked_strategies(call_options, operator)

    assert strategies is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_stake_type_per_quorum(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    expected_stake_type = 42  # Example stake type returned from contract

    # Successful scenario
    avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.return_value = expected_stake_type

    stake_type, error = avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

    assert error is None
    assert stake_type == expected_stake_type
    avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.assert_called_with(quorum_number)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    stake_type, error = avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

    assert stake_type is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Contract call failure
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.side_effect = Exception("Contract call failed")

    stake_type, error = avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

    assert stake_type is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_slashable_stake_look_ahead_per_quorum(avs_registry_reader):
    call_options = {}
    quorum_number = 1
    expected_look_ahead = 100  # Example look-ahead value returned from contract

    # Successful scenario
    avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.return_value = expected_look_ahead

    look_ahead, error = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(call_options, quorum_number)

    assert error is None
    assert look_ahead == expected_look_ahead
    avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.assert_called_with(quorum_number)

    # StakeRegistry missing scenario
    avs_registry_reader.stake_registry = None

    look_ahead, error = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(call_options, quorum_number)

    assert look_ahead is None
    assert isinstance(error, ValueError)
    assert str(error) == "StakeRegistry contract not provided"

    # Contract call failure
    avs_registry_reader.stake_registry = Mock()
    avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.side_effect = Exception("Contract call failed")

    look_ahead, error = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(call_options, quorum_number)

    assert look_ahead is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_operator_id(avs_registry_reader):
    call_options = {}
    operator_address = "0xOperatorAddress"
    expected_operator_id = b'\x12\x34\x56\x78'  # Example operator ID returned from contract

    # Successful scenario
    avs_registry_reader.registry_coordinator.functions.getOperatorId.return_value.call.return_value = expected_operator_id

    operator_id, error = avs_registry_reader.get_operator_id(call_options, operator_address)

    assert error is None
    assert operator_id == expected_operator_id
    avs_registry_reader.registry_coordinator.functions.getOperatorId.assert_called_with(operator_address)

    # RegistryCoordinator missing scenario
    avs_registry_reader.registry_coordinator = None

    operator_id, error = avs_registry_reader.get_operator_id(call_options, operator_address)

    assert operator_id is None
    assert isinstance(error, ValueError)
    assert str(error) == "RegistryCoordinator contract not provided"

    # Contract call failure
    avs_registry_reader.registry_coordinator = Mock()
    avs_registry_reader.registry_coordinator.functions.getOperatorId.return_value.call.side_effect = Exception("Contract call failed")

    operator_id, error = avs_registry_reader.get_operator_id(call_options, operator_address)

    assert operator_id is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_get_operator_from_id(avs_registry_reader):
    call_options = {}
    operator_id = b'\x12\x34\x56\x78'  # Example operator ID
    expected_operator_address = "0xOperatorAddress"

    # Successful scenario
    avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.return_value = expected_operator_address

    operator_address, error = avs_registry_reader.get_operator_from_id(call_options, operator_id)

    assert error is None
    assert operator_address == expected_operator_address
    avs_registry_reader.registry_coordinator.functions.getOperatorFromId.assert_called_with(operator_id)

    # RegistryCoordinator missing scenario
    avs_registry_reader.registry_coordinator = None

    operator_address, error = avs_registry_reader.get_operator_from_id(call_options, operator_id)

    assert operator_address is None
    assert isinstance(error, ValueError)
    assert str(error) == "RegistryCoordinator contract not provided"

    # Contract call failure
    avs_registry_reader.registry_coordinator = Mock()
    avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.side_effect = Exception("Contract call failed")

    operator_address, error = avs_registry_reader.get_operator_from_id(call_options, operator_id)

    assert operator_address is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"


def test_query_registration_detail(avs_registry_reader, mocker):
    call_options = {}
    operator_address = "0xOperatorAddress"
    operator_id = b'\x12\x34\x56\x78'
    quorum_bitmap = 0b1011  # Quorums 0, 1, and 3 are set

    # Mocking `get_operator_id`
    mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=(operator_id, None))

    # Mocking contract call for `getCurrentQuorumBitmap`
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = quorum_bitmap

    # Successful scenario
    quorums, error = avs_registry_reader.query_registration_detail(call_options, operator_address)

    assert error is None
    assert quorums == [True, True, False, True]  # Based on the 0b1011 bitmap

    # Ensure correct contract calls
    avs_registry_reader.get_operator_id.assert_called_with(call_options, operator_address)
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_with(operator_id)

    # Failure in `get_operator_id`
    mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=(None, ValueError("Failed to get operator id")))

    quorums, error = avs_registry_reader.query_registration_detail(call_options, operator_address)

    assert quorums is None
    assert isinstance(error, ValueError)
    assert str(error) == "Failed to get operator id"

    # Empty quorums, fallback to `get_quorum_count`
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = 0
    mocker.patch.object(avs_registry_reader, "get_quorum_count", return_value=(4, None))

    quorums, error = avs_registry_reader.query_registration_detail(call_options, operator_address)

    assert error is None
    assert quorums == [False, False, False, False]

    # Failure in `get_quorum_count`
    mocker.patch.object(avs_registry_reader, "get_quorum_count", return_value=(None, ValueError("Failed to get quorum count")))

    quorums, error = avs_registry_reader.query_registration_detail(call_options, operator_address)

    assert quorums is None
    assert isinstance(error, ValueError)
    assert str(error) == "Failed to get quorum count"

    # Exception in contract call
    avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.side_effect = Exception("Contract call failed")

    quorums, error = avs_registry_reader.query_registration_detail(call_options, operator_address)

    assert quorums is None
    assert isinstance(error, Exception)
    assert str(error) == "Contract call failed"