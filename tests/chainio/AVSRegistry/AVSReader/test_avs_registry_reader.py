import pytest
from dataclasses import dataclass
from typing import List
from unittest.mock import MagicMock
from unittest.mock import Mock, patch, MagicMock, PropertyMock
from web3.contract.contract import Contract
from web3.exceptions import ContractLogicError

from eigensdk._types import OperatorStateRetrieverOperator
from eigensdk.chainio.clients.avsregistry.reader import AvsRegistryReader


# Create a simple Operator class for expected structure
class OperatorObject:
    def __init__(self, address, stake):
        self.Operator = address
        self.Stake = stake


# Define the StakeRegistryTypesStrategyParams class for testing
@dataclass
class StakeRegistryTypesStrategyParams:
    """Python equivalent of IStakeRegistryTypesStrategyParams struct"""

    strategy: str
    multiplier: int


@dataclass
class StakeRegistryTypesStakeUpdate:
    """Python equivalent of IStakeRegistryTypesStakeUpdate struct for testing"""

    update_block_number: int
    next_update_block_number: int
    stake: int


@dataclass
class OperatorStateRetrieverCheckSignaturesIndices:
    """Mock class for testing CheckSignaturesIndices"""

    quorum_apk_indices: List[int]
    non_signer_stake_indices: List[List[int]]


class TestAvsRegistryReader:

    @pytest.fixture
    def avs_registry_reader(self):
        """Create a mock AvsRegistryReader instance with necessary mock objects."""
        registry_coordinator = Mock(spec=Contract)
        bls_apk_registry = Mock(spec=Contract)
        operator_state_retriever = Mock(spec=Contract)
        service_manager = Mock(spec=Contract)
        stake_registry = Mock(spec=Contract)
        logger = Mock()
        eth_client = Mock()
        tx_mgr = Mock()

        reader = AvsRegistryReader(
            registry_coordinator=registry_coordinator,
            registry_coordinator_addr="0x1234567890123456789012345678901234567890",
            bls_apk_registry=bls_apk_registry,
            bls_apk_registry_addr="0x0987654321098765432109876543210987654321",
            operator_state_retriever=operator_state_retriever,
            service_manager=service_manager,
            stake_registry=stake_registry,
            logger=logger,
            eth_client=eth_client,
            tx_mgr=tx_mgr,
        )

        reader.tx_mgr = tx_mgr

        return reader

    def test_init(self, avs_registry_reader):
        assert (
            avs_registry_reader.registry_coordinator_addr
            == "0x1234567890123456789012345678901234567890"
        )
        assert (
            avs_registry_reader.bls_apk_registry_addr
            == "0x0987654321098765432109876543210987654321"
        )
        assert avs_registry_reader.logger is not None
        assert avs_registry_reader.tx_mgr is not None

    def test_get_quorum_count_success(self, avs_registry_reader):
        # Set up the mock to return a specific value
        avs_registry_reader.registry_coordinator.functions.quorumCount().call.return_value = 3

        # Call the method
        quorum_count = avs_registry_reader.get_quorum_count()

        # Verify result
        assert quorum_count == 3

        # Test with custom call options
        custom_options = {"from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"}
        avs_registry_reader.get_quorum_count(custom_options)
        avs_registry_reader.registry_coordinator.functions.quorumCount().call.assert_called_with(
            custom_options
        )

    def test_get_operators_stake_in_quorums_at_current_block_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0x123"}
        quorum_numbers = [0, 1]
        current_block = 1000

        # Mock the eth_client block number
        avs_registry_reader.eth_client.eth.block_number = current_block

        # Create mock operator data using OperatorStateRetrieverOperator instead of OperatorObject
        mock_operator_data = [
            [
                OperatorStateRetrieverOperator(operator="0xabc", stake=100, operator_id=1),
                OperatorStateRetrieverOperator(operator="0xdef", stake=200, operator_id=2),
            ],
            [
                OperatorStateRetrieverOperator(operator="0xghi", stake=300, operator_id=3),
                OperatorStateRetrieverOperator(operator="0xjkl", stake=400, operator_id=4),
            ],
        ]

        # Mock the get_operators_stake_in_quorums_at_block method
        avs_registry_reader.get_operators_stake_in_quorums_at_block = MagicMock(
            return_value=mock_operator_data
        )

        # Call the method
        result = avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
            call_options, quorum_numbers
        )

        # Verify the get_operators_stake_in_quorums_at_block was called with correct parameters
        avs_registry_reader.get_operators_stake_in_quorums_at_block.assert_called_once_with(
            call_options, quorum_numbers, current_block
        )

        # Verify the result matches expected data
        assert result == mock_operator_data
        assert len(result) == 2  # Two quorums
        assert len(result[0]) == 2  # Two operators in first quorum
        assert len(result[1]) == 2  # Two operators in second quorum
        assert result[0][0].operator == "0xabc"
        assert result[0][0].stake == 100
        assert result[0][0].operator_id == 1
        assert result[1][1].operator == "0xjkl"
        assert result[1][1].stake == 400
        assert result[1][1].operator_id == 4

    def test_get_operators_stake_in_quorums_at_block_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0x123"}
        quorum_numbers = [0, 1]
        block_number = 1000

        # Create proper OperatorStateRetrieverOperator objects with operator_id
        mock_operator_data = [
            [
                OperatorStateRetrieverOperator(operator="0xabc", stake=100, operator_id=1),
                OperatorStateRetrieverOperator(operator="0xdef", stake=200, operator_id=2),
            ],
            [
                OperatorStateRetrieverOperator(operator="0xghi", stake=300, operator_id=3),
                OperatorStateRetrieverOperator(operator="0xjkl", stake=400, operator_id=4),
            ],
        ]

        # Mock the contract function and its call
        mock_function = MagicMock()
        mock_function.call.return_value = mock_operator_data
        avs_registry_reader.operator_state_retriever.functions.getOperatorState = MagicMock(
            return_value=mock_function
        )

        # Call the method
        result = avs_registry_reader.get_operators_stake_in_quorums_at_block(
            call_options, quorum_numbers, block_number
        )

        # Verify the function was called with correct parameters
        avs_registry_reader.operator_state_retriever.functions.getOperatorState.assert_called_once_with(
            avs_registry_reader.registry_coordinator_addr, quorum_numbers, block_number
        )

        # Verify the mock function was called with the correct options
        mock_function.call.assert_called_once_with(call_options)

        # Verify the result matches expected data
        assert result == mock_operator_data
        assert len(result) == 2  # Two quorums
        assert len(result[0]) == 2  # Two operators in first quorum
        assert len(result[1]) == 2  # Two operators in second quorum
        assert result[0][0].operator == "0xabc"
        assert result[0][0].stake == 100
        assert result[0][0].operator_id == 1
        assert result[1][1].operator == "0xjkl"
        assert result[1][1].stake == 400
        assert result[1][1].operator_id == 4

    def test_get_operator_addrs_in_quorums_at_current_block_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0x123"}
        quorum_numbers = [0, 1]
        current_block = 1000

        # Mock the eth_client block number
        avs_registry_reader.eth_client.eth.block_number = current_block

        # Mock operator state data returned from contract
        mock_operator_state = [
            [
                {"operator": "0xabc123", "stake": 100},
                {"operator": "0xdef456", "stake": 200},
            ],
            [
                {"operator": "0xghi789", "stake": 300},
                {"operator": "0xjkl012", "stake": 400},
            ],
        ]

        # Mock the contract function call
        mock_function = MagicMock()
        mock_function.call.return_value = mock_operator_state
        avs_registry_reader.operator_state_retriever.functions.getOperatorState = MagicMock(
            return_value=mock_function
        )

        # Expected result after processing
        expected_addresses = [["0xabc123", "0xdef456"], ["0xghi789", "0xjkl012"]]

        # Call the method
        result = avs_registry_reader.get_operator_addrs_in_quorums_at_current_block(
            call_options, quorum_numbers
        )

        # Verify the contract function was called with correct parameters
        avs_registry_reader.operator_state_retriever.functions.getOperatorState.assert_called_once_with(
            avs_registry_reader.registry_coordinator_addr, quorum_numbers, current_block
        )

        # Verify the mock function was called with the correct options
        mock_function.call.assert_called_once_with(call_options)

        # Verify the result matches expected data
        assert result == expected_addresses
        assert len(result) == 2  # Two quorums
        assert len(result[0]) == 2  # Two operators in first quorum
        assert len(result[1]) == 2  # Two operators in second quorum
        assert result[0][0] == "0xabc123"
        assert result[0][1] == "0xdef456"
        assert result[1][0] == "0xghi789"
        assert result[1][1] == "0xjkl012"

    def test_get_operators_stake_in_quorums_of_operator_at_block_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0x123"}
        operator_id = 1
        block_number = 1000
        quorum_bitmap = 5  # Binary: 101 - means operator is in quorums 0 and 2

        # Mock operator stakes data
        mock_operator_stakes = [
            [
                OperatorStateRetrieverOperator(operator="0xabc", stake=100, operator_id=1),
                OperatorStateRetrieverOperator(operator="0xdef", stake=200, operator_id=2),
            ],
            [
                OperatorStateRetrieverOperator(operator="0xghi", stake=300, operator_id=3),
                OperatorStateRetrieverOperator(operator="0xjkl", stake=400, operator_id=4),
            ],
        ]

        # Mock the contract function call to return bitmap and stakes
        mock_function = MagicMock()
        mock_function.call.return_value = (quorum_bitmap, mock_operator_stakes)
        avs_registry_reader.operator_state_retriever.functions.getOperatorState0 = MagicMock(
            return_value=mock_function
        )

        # Expected quorum IDs from bitmap
        expected_quorums = [0, 2]  # From bitmap 101

        # Call the method
        quorums, operator_stakes = (
            avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
                call_options, operator_id, block_number
            )
        )

        # Verify the contract function was called with correct parameters
        avs_registry_reader.operator_state_retriever.functions.getOperatorState0.assert_called_once_with(
            avs_registry_reader.registry_coordinator_addr, operator_id, block_number
        )

        # Verify the mock function was called with the correct options
        mock_function.call.assert_called_once_with(call_options)

        # Verify the results match expected data
        assert quorums == expected_quorums
        assert operator_stakes == mock_operator_stakes

        # Verify the structure of returned data
        assert len(operator_stakes) == 2
        assert len(operator_stakes[0]) == 2
        assert operator_stakes[0][0].operator == "0xabc"
        assert operator_stakes[0][0].stake == 100
        assert operator_stakes[0][0].operator_id == 1
        assert operator_stakes[1][1].operator == "0xjkl"
        assert operator_stakes[1][1].stake == 400
        assert operator_stakes[1][1].operator_id == 4

    def test_get_operators_stake_in_quorums_of_operator_at_current_block_success(
        self, avs_registry_reader
    ):
        # Mock data
        call_options = {"from": "0x123"}
        operator_id = 1
        current_block = 1000

        # Mock the eth_client block number
        avs_registry_reader.eth_client.eth.block_number = current_block

        # Mock return data from get_operators_stake_in_quorums_of_operator_at_block
        expected_quorums = [0, 2]
        expected_stakes = [
            [
                OperatorStateRetrieverOperator(operator="0xabc", stake=100, operator_id=1),
                OperatorStateRetrieverOperator(operator="0xdef", stake=200, operator_id=2),
            ],
            [
                OperatorStateRetrieverOperator(operator="0xghi", stake=300, operator_id=3),
                OperatorStateRetrieverOperator(operator="0xjkl", stake=400, operator_id=4),
            ],
        ]

        # Mock the underlying method
        avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block = MagicMock(
            return_value=(expected_quorums, expected_stakes)
        )

        # Call the method
        quorums, stakes = (
            avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_current_block(
                call_options, operator_id
            )
        )

        # Verify the underlying method was called with correct parameters
        expected_call_options = {**call_options, "block_number": current_block}
        avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block.assert_called_once_with(
            expected_call_options, operator_id, current_block
        )

        # Verify results
        assert quorums == expected_quorums
        assert stakes == expected_stakes
        assert len(stakes) == 2
        assert stakes[0][0].operator == "0xabc"
        assert stakes[0][0].stake == 100
        assert stakes[1][1].operator == "0xjkl"
        assert stakes[1][1].stake == 400

    def test_get_operator_stake_in_quorums_of_operator_at_current_block_success(
        self, avs_registry_reader
    ):
        # Mock data
        operator_id = 42
        current_block = 12345
        call_options = {"from": "0xabc123"}
        quorum_bitmap = 5  # Binary 101 - representing quorums 0 and 2
        expected_quorums = [0, 2]
        expected_stakes = {0: 100, 2: 200}

        # Setup eth_client
        avs_registry_reader.eth_client = Mock()
        avs_registry_reader.eth_client.eth = Mock()
        avs_registry_reader.eth_client.eth.block_number = current_block

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Mock bitmap_to_quorum_ids
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.bitmap_to_quorum_ids",
            return_value=expected_quorums,
        ):
            # Mock getCurrentStake for each quorum
            avs_registry_reader.stake_registry.functions.getCurrentStake.side_effect = (
                lambda op_id, quorum: Mock(call=lambda opts: expected_stakes[quorum])
            )

            # Call the method
            quorum_stakes = (
                avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
                    call_options, operator_id
                )
            )

            # Verify results
            assert quorum_stakes == expected_stakes

            # Verify the contract methods were called with correct parameters
            avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_once_with(
                operator_id
            )
            avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.assert_called_once()

            # Verify getCurrentStake was called for each quorum
            assert avs_registry_reader.stake_registry.functions.getCurrentStake.call_count == len(
                expected_quorums
            )

    def test_get_operator_stake_in_quorums_of_operator_at_current_block_with_existing_block_number(
        self, avs_registry_reader
    ):
        # Mock data
        operator_id = 42
        existing_block = 54321
        call_options = {"from": "0xabc123", "block_number": existing_block}
        quorum_bitmap = 1  # Just quorum 0
        expected_quorums = [0]
        expected_stakes = {0: 150}

        # Setup eth_client - should NOT be used since block_number is already in call_options
        avs_registry_reader.eth_client = Mock()

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Mock bitmap_to_quorum_ids
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.bitmap_to_quorum_ids",
            return_value=expected_quorums,
        ):
            # Mock getCurrentStake
            avs_registry_reader.stake_registry.functions.getCurrentStake.side_effect = (
                lambda op_id, quorum: Mock(call=lambda opts: expected_stakes[quorum])
            )

            # Call the method
            quorum_stakes = (
                avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
                    call_options, operator_id
                )
            )

            # Verify results
            assert quorum_stakes == expected_stakes

            # Verify eth_client was not accessed (block_number was already in call_options)
            assert (
                not avs_registry_reader.eth_client.eth.block_number.called
                if hasattr(avs_registry_reader.eth_client.eth.block_number, "called")
                else True
            )

    def test_get_operator_stake_in_quorums_of_operator_at_current_block_no_registry_coordinator(
        self, avs_registry_reader
    ):
        # Mock data
        operator_id = 42
        call_options = {"from": "0xabc123"}

        # Setup eth_client
        avs_registry_reader.eth_client = Mock()
        avs_registry_reader.eth_client.eth = Mock()
        avs_registry_reader.eth_client.eth.block_number = 12345

        # Set registry_coordinator to None
        avs_registry_reader.registry_coordinator = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
                call_options, operator_id
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_stake_in_quorums_of_operator_at_current_block_no_stake_registry(
        self, avs_registry_reader
    ):
        # Mock data
        operator_id = 42
        call_options = {"from": "0xabc123"}
        quorum_bitmap = 5  # Binary 101 - representing quorums 0 and 2
        expected_quorums = [0, 2]

        # Setup eth_client
        avs_registry_reader.eth_client = Mock()
        avs_registry_reader.eth_client.eth = Mock()
        avs_registry_reader.eth_client.eth.block_number = 12345

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Mock bitmap_to_quorum_ids
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.bitmap_to_quorum_ids",
            return_value=expected_quorums,
        ):
            # Set stake_registry to None
            avs_registry_reader.stake_registry = None

            # Call the method - it should raise an AttributeError
            with pytest.raises(AttributeError) as excinfo:
                avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
                    call_options, operator_id
                )

            # Verify the error message refers to NoneType
            assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_bitmap_to_quorum_ids(self):
        # Test cases for the bitmap_to_quorum_ids function
        from eigensdk.chainio.chainio_utils.utils import bitmap_to_quorum_ids

        # Test empty bitmap (0)
        assert bitmap_to_quorum_ids(0) == []

        # Test bitmap with single bit set (1 - only quorum 0)
        assert bitmap_to_quorum_ids(1) == [0]

        # Test bitmap with multiple bits set (5 - quorums 0 and 2)
        assert bitmap_to_quorum_ids(5) == [0, 2]

        # Test bitmap with all bits set in first byte (255)
        assert bitmap_to_quorum_ids(255) == [0, 1, 2, 3, 4, 5, 6, 7]

        # Test with custom max_number_of_quorums
        assert bitmap_to_quorum_ids(5, max_number_of_quorums=3) == [0, 2]

    def test_weight_of_operator_for_quorum_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        operator_addr = "0xoperator123"
        call_options = {"from": "0xabc123"}
        expected_weight = 1000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.return_value = (
            expected_weight
        )

        # Call the method
        weight = avs_registry_reader.weight_of_operator_for_quorum(
            call_options, quorum_number, operator_addr
        )

        # Verify results
        assert weight == expected_weight

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.assert_called_once_with(
            quorum_number, operator_addr
        )
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_weight_of_operator_for_quorum_with_custom_options(self, avs_registry_reader):
        # Mock data
        quorum_number = 0
        operator_addr = "0xoperator456"
        custom_options = {"from": "0xabc123", "block_number": 12345}
        expected_weight = 500

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.return_value = (
            expected_weight
        )

        # Call the method
        weight = avs_registry_reader.weight_of_operator_for_quorum(
            custom_options, quorum_number, operator_addr
        )

        # Verify results
        assert weight == expected_weight

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.assert_called_once_with(
            quorum_number, operator_addr
        )
        avs_registry_reader.stake_registry.functions.weightOfOperatorForQuorum.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_weight_of_operator_for_quorum_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        operator_addr = "0xoperator789"
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.weight_of_operator_for_quorum(
                call_options, quorum_number, operator_addr
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_strategy_params_length_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0x123"}
        quorum_number = 1
        expected_length = 3

        # Mock the contract function call
        mock_function = MagicMock()
        mock_function.call.return_value = expected_length
        avs_registry_reader.stake_registry.functions.strategyParamsLength = MagicMock(
            return_value=mock_function
        )

        # Call the method
        result = avs_registry_reader.strategy_params_length(call_options, quorum_number)

        # Verify the contract function was called with correct parameters
        avs_registry_reader.stake_registry.functions.strategyParamsLength.assert_called_once_with(
            quorum_number
        )

        # Verify the mock function was called with the correct options
        mock_function.call.assert_called_once_with(call_options)

        # Verify result
        assert result == expected_length

    def test_strategy_params_by_index_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        index = 1
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.strategy_params_by_index(call_options, quorum_number, index)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_history_length_success(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_length = 5

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.return_value = (
            expected_length
        )

        # Call the method
        length = avs_registry_reader.get_stake_history_length(
            call_options, operator_id, quorum_number
        )

        # Verify results
        assert length == expected_length

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.assert_called_once_with(
            operator_id, quorum_number
        )
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_stake_history_length_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_id = 123
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_length = 10

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.return_value = (
            expected_length
        )

        # Call the method
        length = avs_registry_reader.get_stake_history_length(
            custom_options, operator_id, quorum_number
        )

        # Verify results
        assert length == expected_length

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.assert_called_once_with(
            operator_id, quorum_number
        )
        avs_registry_reader.stake_registry.functions.getStakeHistoryLength.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_stake_history_length_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_history_length(call_options, operator_id, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_history_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_history(call_options, operator_id, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_latest_stake_update_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_latest_stake_update(call_options, operator_id, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_update_at_index_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        index = 0
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_update_at_index(
                call_options, operator_id, quorum_number, index
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_at_block_number_success(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 3
        block_number = 12345
        call_options = {"from": "0xabc123"}
        expected_stake = 1500

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_stake_at_block_number(
            call_options, operator_id, quorum_number, block_number
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.assert_called_once_with(
            operator_id, quorum_number, block_number
        )
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_stake_at_block_number_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_id = 123
        quorum_number = 1
        block_number = 54321
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_stake = 2000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_stake_at_block_number(
            custom_options, operator_id, quorum_number, block_number
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.assert_called_once_with(
            operator_id, quorum_number, block_number
        )
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_stake_at_block_number_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        block_number = 12345
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_at_block_number(
                call_options, operator_id, quorum_number, block_number
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_at_block_number_zero_stake(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 0
        block_number = 12345
        call_options = {"from": "0xabc123"}
        expected_stake = 0  # Testing with zero stake

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_stake_at_block_number(
            call_options, operator_id, quorum_number, block_number
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.assert_called_once_with(
            operator_id, quorum_number, block_number
        )
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumber.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_stake_update_index_at_block_number_success(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 3
        block_number = 12345
        call_options = {"from": "0xabc123"}
        expected_index = 2

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.return_value = (
            expected_index
        )

        # Call the method
        index = avs_registry_reader.get_stake_update_index_at_block_number(
            call_options, operator_id, quorum_number, block_number
        )

        # Verify results
        assert index == expected_index

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.assert_called_once_with(
            operator_id, quorum_number, block_number
        )
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_stake_update_index_at_block_number_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_id = 123
        quorum_number = 1
        block_number = 54321
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_index = 3

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.return_value = (
            expected_index
        )

        # Call the method
        index = avs_registry_reader.get_stake_update_index_at_block_number(
            custom_options, operator_id, quorum_number, block_number
        )

        # Verify results
        assert index == expected_index

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.assert_called_once_with(
            operator_id, quorum_number, block_number
        )
        avs_registry_reader.stake_registry.functions.getStakeUpdateIndexAtBlockNumber.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_stake_update_index_at_block_number_no_stake_registry(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 2
        block_number = 12345
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_update_index_at_block_number(
                call_options, operator_id, quorum_number, block_number
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_at_block_number_and_index_success(self, avs_registry_reader):
        # Mock data
        operator_id = 42
        quorum_number = 3
        block_number = 12345
        index = 2
        call_options = {"from": "0xabc123"}
        expected_stake = 1500

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_stake_at_block_number_and_index(
            call_options, operator_id, quorum_number, block_number, index
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.assert_called_once_with(
            quorum_number, block_number, operator_id, index
        )
        avs_registry_reader.stake_registry.functions.getStakeAtBlockNumberAndIndex.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_history_length_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_length = 10

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.return_value = (
            expected_length
        )

        # Call the method
        length = avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

        # Verify results
        assert length == expected_length

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_history_length_with_custom_options(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_length = 5

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.return_value = (
            expected_length
        )

        # Call the method
        length = avs_registry_reader.get_total_stake_history_length(custom_options, quorum_number)

        # Verify results
        assert length == expected_length

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_total_stake_history_length_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_total_stake_history_length_zero(self, avs_registry_reader):
        # Mock data - test with length of 0 (edge case)
        quorum_number = 0
        call_options = {"from": "0xabc123"}
        expected_length = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.return_value = (
            expected_length
        )

        # Call the method
        length = avs_registry_reader.get_total_stake_history_length(call_options, quorum_number)

        # Verify results
        assert length == expected_length

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeHistoryLength.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_check_signatures_indices_no_operator_state_retriever(self, avs_registry_reader):
        # Mock data
        reference_block_number = 12345
        quorum_numbers = [0, 1]
        non_signer_operator_ids = [42, 43]
        call_options = {"from": "0xabc123"}

        # Set operator_state_retriever to None
        avs_registry_reader.operator_state_retriever = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_check_signatures_indices(
                call_options,
                reference_block_number,
                quorum_numbers,
                non_signer_operator_ids,
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_current_total_stake_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_stake = 5000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_current_total_stake(call_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_current_total_stake_with_custom_options(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_stake = 10000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_current_total_stake(custom_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_current_total_stake_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_current_total_stake(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_current_total_stake_zero(self, avs_registry_reader):
        # Mock data - test with a total stake of 0 (edge case)
        quorum_number = 0
        call_options = {"from": "0xabc123"}
        expected_stake = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_current_total_stake(call_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.getCurrentTotalStake.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_update_at_index_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        index = 0
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_total_stake_update_at_index(call_options, quorum_number, index)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_total_stake_at_block_number_from_index_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        block_number = 12345
        index = 2
        call_options = {"from": "0xabc123"}
        expected_stake = 5000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_total_stake_at_block_number_from_index(
            call_options, quorum_number, block_number, index
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.assert_called_once_with(
            quorum_number, block_number, index
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_at_block_number_from_index_with_custom_options(
        self, avs_registry_reader
    ):
        # Mock data
        quorum_number = 1
        block_number = 54321
        index = 3
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_stake = 8000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_total_stake_at_block_number_from_index(
            custom_options, quorum_number, block_number, index
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.assert_called_once_with(
            quorum_number, block_number, index
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_total_stake_at_block_number_from_index_no_stake_registry(
        self, avs_registry_reader
    ):
        # Mock data
        quorum_number = 2
        block_number = 12345
        index = 1
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_total_stake_at_block_number_from_index(
                call_options, quorum_number, block_number, index
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_total_stake_at_block_number_from_index_zero_stake(self, avs_registry_reader):
        # Mock data - testing with a zero stake (edge case)
        quorum_number = 0
        block_number = 12345
        index = 0
        call_options = {"from": "0xabc123"}
        expected_stake = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_total_stake_at_block_number_from_index(
            call_options, quorum_number, block_number, index
        )

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.assert_called_once_with(
            quorum_number, block_number, index
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeAtBlockNumberFromIndex.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_indices_at_block_number_success(self, avs_registry_reader):
        # Mock data
        quorum_numbers = [0, 1, 2]  # Use actual list instead of Mock
        block_number = 12345
        call_options = {"from": "0xabc123"}
        expected_indices = [3, 5, 7]  # One index per quorum

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.return_value.call.return_value = (
            expected_indices
        )

        # Call the method
        indices = avs_registry_reader.get_total_stake_indices_at_block_number(
            call_options, quorum_numbers, block_number
        )

        # Verify results
        assert indices == expected_indices

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.assert_called_once_with(
            block_number, quorum_numbers
        )
        avs_registry_reader.stake_registry.functions.getTotalStakeIndicesAtBlockNumber.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_total_stake_indices_at_block_number_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_numbers = [0, 1]
        block_number = 12345
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_total_stake_indices_at_block_number(
                call_options, quorum_numbers, block_number
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_minimum_stake_for_quorum_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_stake = 100000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_minimum_stake_for_quorum_with_custom_options(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_stake = 500000

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_minimum_stake_for_quorum(custom_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_minimum_stake_for_quorum_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_minimum_stake_for_quorum_zero_stake(self, avs_registry_reader):
        # Mock data - testing with a zero minimum stake (edge case)
        quorum_number = 0
        call_options = {"from": "0xabc123"}
        expected_stake = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.return_value = (
            expected_stake
        )

        # Call the method
        stake = avs_registry_reader.get_minimum_stake_for_quorum(call_options, quorum_number)

        # Verify results
        assert stake == expected_stake

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.minimumStakeForQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_strategy_params_at_index_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        index = 1
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_strategy_params_at_index(call_options, quorum_number, index)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_strategy_per_quorum_at_index_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        index = 1
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_strategy_per_quorum_at_index(call_options, quorum_number, index)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_restakeable_strategies_success(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0xabc123"}
        raw_strategies = [
            "0xstrategy1",
            "0xstrategy2",
            "0xstrategy1",  # Duplicate to be removed
            "0xstrategy3",
        ]
        expected_unique_strategies = ["0xstrategy1", "0xstrategy2", "0xstrategy3"]

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.return_value = (
            raw_strategies
        )

        # Mock the remove_duplicate_strategies function
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=expected_unique_strategies,
        ) as mock_remove_duplicates:

            # Call the method
            strategies = avs_registry_reader.get_restakeable_strategies(call_options)

            # Verify results
            assert strategies == expected_unique_strategies

            # Verify the contract method was called with correct parameters
            avs_registry_reader.service_manager.functions.getRestakeableStrategies.assert_called_once()
            avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.assert_called_once_with(
                call_options
            )

            # Verify remove_duplicate_strategies was called with the raw strategies
            mock_remove_duplicates.assert_called_once_with(raw_strategies)

    def test_get_restakeable_strategies_empty_list(self, avs_registry_reader):
        # Mock data - test with empty list
        call_options = {"from": "0xabc123"}
        empty_strategies = []

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.return_value = (
            empty_strategies
        )

        # Mock the remove_duplicate_strategies function to return empty list
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=[],
        ) as mock_remove_duplicates:

            # Call the method
            strategies = avs_registry_reader.get_restakeable_strategies(call_options)

            # Verify results
            assert strategies == []
            assert len(strategies) == 0

            # Verify the contract method was called with correct parameters
            avs_registry_reader.service_manager.functions.getRestakeableStrategies.assert_called_once()
            avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.assert_called_once_with(
                call_options
            )

            # Verify remove_duplicate_strategies was called with the empty list
            mock_remove_duplicates.assert_called_once_with(empty_strategies)

    def test_get_restakeable_strategies_no_service_manager(self, avs_registry_reader):
        # Mock data
        call_options = {"from": "0xabc123"}

        # Set service_manager to None
        avs_registry_reader.service_manager = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_restakeable_strategies(call_options)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_restakeable_strategies_with_custom_options(self, avs_registry_reader):
        # Mock data
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        raw_strategies = ["0xstrategy1", "0xstrategy2"]
        expected_unique_strategies = ["0xstrategy1", "0xstrategy2"]  # Already unique

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.return_value = (
            raw_strategies
        )

        # Mock the remove_duplicate_strategies function
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=expected_unique_strategies,
        ):

            # Call the method
            strategies, error = avs_registry_reader.get_restakeable_strategies(custom_options)

            # Verify custom options were passed through correctly
            avs_registry_reader.service_manager.functions.getRestakeableStrategies.return_value.call.assert_called_once_with(
                custom_options
            )

    def test_get_operator_restaked_strategies_success(self, avs_registry_reader):
        # Mock data
        operator_address = "0xoperator123"
        call_options = {"from": "0xabc123"}
        raw_strategies = [
            "0xstrategy1",
            "0xstrategy2",
            "0xstrategy1",  # Duplicate to be removed
            "0xstrategy3",
        ]
        expected_unique_strategies = ["0xstrategy1", "0xstrategy2", "0xstrategy3"]

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.return_value = (
            raw_strategies
        )

        # Mock the remove_duplicate_strategies function
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=expected_unique_strategies,
        ) as mock_remove_duplicates:

            # Call the method
            strategies = avs_registry_reader.get_operator_restaked_strategies(
                call_options, operator_address
            )

            # Verify results
            assert strategies == expected_unique_strategies

            # Verify the contract method was called with correct parameters
            avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.assert_called_once_with(
                operator_address
            )
            avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.assert_called_once_with(
                call_options
            )

            # Verify remove_duplicate_strategies was called with the raw strategies
            mock_remove_duplicates.assert_called_once_with(raw_strategies)

    def test_get_operator_restaked_strategies_empty_list(self, avs_registry_reader):
        # Mock data - test with empty list
        operator_address = "0xoperator123"
        call_options = {"from": "0xabc123"}
        empty_strategies = []

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.return_value = (
            empty_strategies
        )

        # Mock the remove_duplicate_strategies function
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=[],
        ) as mock_remove_duplicates:

            # Call the method
            strategies = avs_registry_reader.get_operator_restaked_strategies(
                call_options, operator_address
            )

            # Verify results
            assert strategies == []
            assert len(strategies) == 0

            # Verify the contract method was called with correct parameters
            avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.assert_called_once_with(
                operator_address
            )
            avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.assert_called_once_with(
                call_options
            )

            # Verify remove_duplicate_strategies was called with the empty list
            mock_remove_duplicates.assert_called_once_with(empty_strategies)

    def test_get_operator_restaked_strategies_no_service_manager(self, avs_registry_reader):
        # Mock data
        operator_address = "0xoperator123"
        call_options = {"from": "0xabc123"}

        # Set service_manager to None
        avs_registry_reader.service_manager = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_restaked_strategies(call_options, operator_address)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_restaked_strategies_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_address = "0xoperator123"
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        raw_strategies = ["0xstrategy1", "0xstrategy2"]
        expected_unique_strategies = ["0xstrategy1", "0xstrategy2"]  # Already unique

        # Mock the service_manager
        avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.return_value = (
            raw_strategies
        )

        # Mock the remove_duplicate_strategies function
        with patch(
            "eigensdk.chainio.clients.avsregistry.reader.remove_duplicate_strategies",
            return_value=expected_unique_strategies,
        ):

            # Call the method
            strategies, error = avs_registry_reader.get_operator_restaked_strategies(
                custom_options, operator_address
            )

            # Verify custom options were passed through correctly
            avs_registry_reader.service_manager.functions.getOperatorRestakedStrategies.return_value.call.assert_called_once_with(
                custom_options
            )

    def test_get_stake_type_per_quorum_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_stake_type = 1  # Assuming 1 represents a specific stake type

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.return_value = (
            expected_stake_type
        )

        # Call the method
        stake_type = avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

        # Verify results
        assert stake_type == expected_stake_type

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_stake_type_per_quorum_with_custom_options(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_stake_type = 2  # Different stake type

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.return_value = (
            expected_stake_type
        )

        # Call the method
        stake_type = avs_registry_reader.get_stake_type_per_quorum(custom_options, quorum_number)

        # Verify results
        assert stake_type == expected_stake_type

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_stake_type_per_quorum_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_stake_type_per_quorum_zero(self, avs_registry_reader):
        # Mock data - testing with a stake type of 0 (edge case)
        quorum_number = 0
        call_options = {"from": "0xabc123"}
        expected_stake_type = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.return_value = (
            expected_stake_type
        )

        # Call the method
        stake_type = avs_registry_reader.get_stake_type_per_quorum(call_options, quorum_number)

        # Verify results
        assert stake_type == expected_stake_type

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.stakeTypePerQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_slashable_stake_look_ahead_per_quorum_success(self, avs_registry_reader):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xabc123"}
        expected_look_ahead = 100  # Some number of blocks for look ahead

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.return_value = (
            expected_look_ahead
        )

        # Call the method
        look_ahead = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
            call_options, quorum_number
        )

        # Verify results
        assert look_ahead == expected_look_ahead

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_slashable_stake_look_ahead_per_quorum_with_custom_options(
        self, avs_registry_reader
    ):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xabc123", "gasLimit": 200000}
        expected_look_ahead = 200  # Different look ahead value

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.return_value = (
            expected_look_ahead
        )

        # Call the method
        look_ahead = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
            custom_options, quorum_number
        )

        # Verify results
        assert look_ahead == expected_look_ahead

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_slashable_stake_look_ahead_per_quorum_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xabc123"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
                call_options, quorum_number
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_slashable_stake_look_ahead_per_quorum_exception(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        call_options = {"from": "0xabc123"}

        # Mock the stake_registry to raise an exception
        mock_exception = Exception("Failed to get slashable stake look ahead")
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.side_effect = (
            mock_exception
        )

        # Call the method - it should raise the exception
        with pytest.raises(Exception) as excinfo:
            avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
                call_options, quorum_number
            )

        # Verify the error message
        assert "Failed to get slashable stake look ahead" in str(excinfo.value)

    def test_get_slashable_stake_look_ahead_per_quorum_zero(self, avs_registry_reader):
        # Mock data - testing with a look ahead of 0 (edge case)
        quorum_number = 0
        call_options = {"from": "0xabc123"}
        expected_look_ahead = 0

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.return_value = (
            expected_look_ahead
        )

        # Call the method
        look_ahead = avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(
            call_options, quorum_number
        )

        # Verify results
        assert look_ahead == expected_look_ahead

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.slashableStakeLookAheadPerQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_id_no_registry_coordinator(self, avs_registry_reader):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}

        # Set registry_coordinator to None
        avs_registry_reader.registry_coordinator = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_id(call_options, operator_address)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_from_id_success(self, avs_registry_reader):
        # Mock data
        operator_id = 123456  # Example operator ID
        call_options = {"from": "0xuser789"}
        expected_operator_address = "0xabc123def456"  # Expected operator address

        # Mock the registry_coordinator
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_from_id(call_options, operator_id)

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_from_id_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_id = 789012
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        expected_operator_address = "0xdef456abc789"

        # Mock the registry_coordinator
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_from_id(custom_options, operator_id)

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_operator_from_id_no_registry_coordinator(self, avs_registry_reader):
        # Mock data
        operator_id = 123456
        call_options = {"from": "0xuser789"}

        # Set registry_coordinator to None
        avs_registry_reader.registry_coordinator = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_from_id(call_options, operator_id)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_from_id_zero(self, avs_registry_reader):
        # Test with operator_id = 0 (edge case)
        operator_id = 0
        call_options = {"from": "0xuser789"}
        expected_operator_address = (
            "0x0000000000000000000000000000000000000000"  # Hypothetical address for ID 0
        )

        # Mock the registry_coordinator
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_from_id(call_options, operator_id)

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getOperatorFromId.return_value.call.assert_called_once_with(
            call_options
        )

    def test_query_registration_detail_success_with_active_quorums(
        self, avs_registry_reader, mocker
    ):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_id = 12345
        quorum_bitmap = 21  # Binary: 10101 - quorums 0, 2, and 4 are active
        expected_quorums = [
            True,
            False,
            True,
            False,
            True,
        ]  # Corresponding boolean list

        # Mock get_operator_id - now returns only the id, not a tuple
        mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=operator_id)

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Call the method
        quorums = avs_registry_reader.query_registration_detail(call_options, operator_address)

        # Verify results
        assert quorums == expected_quorums

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.assert_called_once_with(
            call_options
        )

    def test_query_registration_detail_success_no_active_quorums(self, avs_registry_reader, mocker):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_id = 12345
        quorum_bitmap = 0  # No active quorums
        expected_quorums = []  # No active quorums means empty list

        # Mock get_operator_id - now returns only the id, not a tuple
        mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=operator_id)

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Call the method
        quorums = avs_registry_reader.query_registration_detail(call_options, operator_address)

        # Verify results
        assert quorums == expected_quorums  # Should be an empty list since bitmap is 0

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.assert_called_once_with(
            call_options
        )

    def test_query_registration_detail_get_operator_id_failure(self, avs_registry_reader, mocker):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_error = ValueError("Operator not found")

        # Mock get_operator_id to raise an exception
        mocker.patch.object(avs_registry_reader, "get_operator_id", side_effect=operator_error)

        # Call the method - should now raise the exception
        with pytest.raises(ValueError) as excinfo:
            avs_registry_reader.query_registration_detail(call_options, operator_address)

        # Verify the error message
        assert "Operator not found" in str(excinfo.value)

    def test_query_registration_detail_get_quorum_count_failure(self, avs_registry_reader, mocker):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_id = 12345
        quorum_bitmap = 0  # No active quorums

        # Mock get_operator_id - now returns only the id, not a tuple
        mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=operator_id)

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Call the method
        quorums = avs_registry_reader.query_registration_detail(call_options, operator_address)

        # Verify results - when bitmap is 0, we get an empty list
        assert quorums == []

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.assert_called_once_with(
            call_options
        )

    def test_query_registration_detail_complex_bitmap(self, avs_registry_reader, mocker):
        # Mock data with a more complex bitmap
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_id = 12345
        quorum_bitmap = 682  # Binary: 1010101010 - alternating pattern with 10 bits
        expected_quorums = [
            False,
            True,
            False,
            True,
            False,
            True,
            False,
            True,
            False,
            True,
        ]

        # Mock get_operator_id - now returns only the id, not a tuple
        mocker.patch.object(avs_registry_reader, "get_operator_id", return_value=operator_id)

        # Mock getCurrentQuorumBitmap
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.return_value = (
            quorum_bitmap
        )

        # Call the method
        quorums = avs_registry_reader.query_registration_detail(call_options, operator_address)

        # Verify results
        assert quorums == expected_quorums

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.assert_called_once_with(
            operator_id
        )
        avs_registry_reader.registry_coordinator.functions.getCurrentQuorumBitmap.return_value.call.assert_called_once_with(
            call_options
        )

    def test_is_operator_registered_success_registered(self, avs_registry_reader):
        # Mock data for a registered operator
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        operator_status = 1  # Status 1 indicates registered

        # Mock the registry_coordinator
        avs_registry_reader.registry_coordinator.functions.getOperatorStatus.return_value.call.return_value = (
            operator_status
        )

        # Call the method
        registered = avs_registry_reader.is_operator_registered(call_options, operator_address)

        # Verify results
        assert registered is True

        # Verify the contract method was called with correct parameters
        avs_registry_reader.registry_coordinator.functions.getOperatorStatus.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.registry_coordinator.functions.getOperatorStatus.return_value.call.assert_called_once_with(
            call_options
        )

    def test_is_operator_registered_no_registry_coordinator(self, avs_registry_reader):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}

        # Set registry_coordinator to None
        avs_registry_reader.registry_coordinator = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.is_operator_registered(call_options, operator_address)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_is_operator_set_quorum_success_true(self, avs_registry_reader):
        # Mock data for a quorum that is an operator set quorum
        quorum_number = 3
        call_options = {"from": "0xuser789"}

        # Mock the stake_registry to return True
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.return_value = (
            True
        )

        # Call the method
        is_operator_set = avs_registry_reader.is_operator_set_quorum(call_options, quorum_number)

        # Verify results
        assert is_operator_set is True

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_is_operator_set_quorum_success_false(self, avs_registry_reader):
        # Mock data for a quorum that is not an operator set quorum
        quorum_number = 2
        call_options = {"from": "0xuser789"}

        # Mock the stake_registry to return False
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.return_value = (
            False
        )

        # Call the method
        is_operator_set = avs_registry_reader.is_operator_set_quorum(call_options, quorum_number)

        # Verify results
        assert is_operator_set is False

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_is_operator_set_quorum_no_stake_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 1
        call_options = {"from": "0xuser789"}

        # Set stake_registry to None
        avs_registry_reader.stake_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.is_operator_set_quorum(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_is_operator_set_quorum_edge_case_zero(self, avs_registry_reader):
        # Testing with quorum_number = 0 (edge case)
        quorum_number = 0
        call_options = {"from": "0xuser789"}

        # Mock the stake_registry
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.return_value = (
            False
        )

        # Call the method
        is_operator_set = avs_registry_reader.is_operator_set_quorum(call_options, quorum_number)

        # Verify results
        assert is_operator_set is False

        # Verify the contract method was called with correct parameters
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.stake_registry.functions.isOperatorSetQuorum.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_id_from_operator_address_success(self, avs_registry_reader):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        expected_pubkey_hash = (
            b"\x01\x02\x03\x04\x05\x06\x07\x08"  # Example bytes value as pubkey hash
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.return_value = (
            expected_pubkey_hash
        )

        # Call the method
        pubkey_hash = avs_registry_reader.get_operator_id_from_operator_address(
            call_options, operator_address
        )

        # Verify results
        assert pubkey_hash == expected_pubkey_hash

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_id_from_operator_address_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_address = "0xdef456abc789"
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        expected_pubkey_hash = b"\x08\x07\x06\x05\x04\x03\x02\x01"  # Different pubkey hash

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.return_value = (
            expected_pubkey_hash
        )

        # Call the method
        pubkey_hash = avs_registry_reader.get_operator_id_from_operator_address(
            custom_options, operator_address
        )

        # Verify results
        assert pubkey_hash == expected_pubkey_hash

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_operator_id_from_operator_address_no_bls_apk_registry(self, avs_registry_reader):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}

        # Set bls_apk_registry to None
        avs_registry_reader.bls_apk_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_id_from_operator_address(
                call_options, operator_address
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_id_from_operator_address_zero_address(self, avs_registry_reader):
        # Testing with zero address (edge case)
        operator_address = "0x0000000000000000000000000000000000000000"
        call_options = {"from": "0xuser789"}
        expected_pubkey_hash = b"\x00" * 32  # All zeros pubkey hash

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.return_value = (
            expected_pubkey_hash
        )

        # Call the method
        pubkey_hash = avs_registry_reader.get_operator_id_from_operator_address(
            call_options, operator_address
        )

        # Verify results
        assert pubkey_hash == expected_pubkey_hash

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkeyHash.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_address_from_operator_id_success(self, avs_registry_reader):
        # Mock data
        operator_pubkey_hash = (
            b"\x01\x02\x03\x04\x05\x06\x07\x08"  # Example bytes value as pubkey hash
        )
        call_options = {"from": "0xuser789"}
        expected_operator_address = "0xabc123def456"

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_address_from_operator_id(
            call_options, operator_pubkey_hash
        )

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.assert_called_once_with(
            operator_pubkey_hash
        )
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_operator_address_from_operator_id_with_custom_options(self, avs_registry_reader):
        # Mock data
        operator_pubkey_hash = b"\x08\x07\x06\x05\x04\x03\x02\x01"  # Different pubkey hash
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        expected_operator_address = "0xdef456abc789"

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_address_from_operator_id(
            custom_options, operator_pubkey_hash
        )

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.assert_called_once_with(
            operator_pubkey_hash
        )
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.assert_called_once_with(
            custom_options
        )

    def test_get_operator_address_from_operator_id_no_bls_apk_registry(self, avs_registry_reader):
        # Mock data
        operator_pubkey_hash = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        call_options = {"from": "0xuser789"}

        # Set bls_apk_registry to None
        avs_registry_reader.bls_apk_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_operator_address_from_operator_id(
                call_options, operator_pubkey_hash
            )

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_operator_address_from_operator_id_empty_pubkey_hash(self, avs_registry_reader):
        # Testing with empty pubkey hash (edge case)
        operator_pubkey_hash = b""
        call_options = {"from": "0xuser789"}
        expected_operator_address = "0x0000000000000000000000000000000000000000"  # Zero address

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.return_value = (
            expected_operator_address
        )

        # Call the method
        operator_address = avs_registry_reader.get_operator_address_from_operator_id(
            call_options, operator_pubkey_hash
        )

        # Verify results
        assert operator_address == expected_operator_address

        # Verify the contract method was called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.assert_called_once_with(
            operator_pubkey_hash
        )
        avs_registry_reader.bls_apk_registry.functions.pubkeyHashToOperator.return_value.call.assert_called_once_with(
            call_options
        )

    def test_get_pubkey_from_operator_address_success(self, avs_registry_reader, mocker):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}
        pubkey_x = 123456
        pubkey_y = 789012
        mock_pubkey = {"x": pubkey_x, "y": pubkey_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.return_value = (
            mock_pubkey
        )

        # Call the method
        pubkey = avs_registry_reader.get_pubkey_from_operator_address(
            call_options, operator_address
        )

        # Verify results
        assert pubkey == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.assert_called_once_with(
            call_options
        )
        G1Point_mock.assert_called_once_with(pubkey_x, pubkey_y)

    def test_get_pubkey_from_operator_address_with_custom_options(
        self, avs_registry_reader, mocker
    ):
        # Mock data
        operator_address = "0xdef456abc789"
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        pubkey_x = 111222
        pubkey_y = 333444
        mock_pubkey = {"x": pubkey_x, "y": pubkey_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.return_value = (
            mock_pubkey
        )

        # Call the method
        pubkey = avs_registry_reader.get_pubkey_from_operator_address(
            custom_options, operator_address
        )

        # Verify results
        assert pubkey == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.assert_called_once_with(
            custom_options
        )
        G1Point_mock.assert_called_once_with(pubkey_x, pubkey_y)

    def test_get_pubkey_from_operator_address_no_bls_apk_registry(self, avs_registry_reader):
        # Mock data
        operator_address = "0xabc123def456"
        call_options = {"from": "0xuser789"}

        # Set bls_apk_registry to None
        avs_registry_reader.bls_apk_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_pubkey_from_operator_address(call_options, operator_address)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_pubkey_from_operator_address_zero_address(self, avs_registry_reader, mocker):
        # Testing with zero address (edge case)
        operator_address = "0x0000000000000000000000000000000000000000"
        call_options = {"from": "0xuser789"}
        pubkey_x = 0
        pubkey_y = 0
        mock_pubkey = {"x": pubkey_x, "y": pubkey_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.return_value = (
            mock_pubkey
        )

        # Call the method
        pubkey = avs_registry_reader.get_pubkey_from_operator_address(
            call_options, operator_address
        )

        # Verify results
        assert pubkey == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.assert_called_once_with(
            operator_address
        )
        avs_registry_reader.bls_apk_registry.functions.operatorToPubkey.return_value.call.assert_called_once_with(
            call_options
        )
        G1Point_mock.assert_called_once_with(pubkey_x, pubkey_y)

    def test_get_apk_update_success(self, avs_registry_reader, mocker):
        # Mock data
        quorum_number = 3
        index = 5
        call_options = {"from": "0xuser789"}
        mock_update_data = {
            "apkHash": b"\x01\x02\x03\x04",
            "updateBlockNumber": 1000,
            "nextUpdateBlockNumber": 2000,
        }

        # Mock BLSApkRegistryTypesApkUpdate class
        mock_apk_update = mocker.Mock()
        BLSApkRegistryTypesApkUpdate_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.BLSApkRegistryTypesApkUpdate",
            return_value=mock_apk_update,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.apkHistory.return_value.call.return_value = (
            mock_update_data
        )

        # Call the method
        apk_update = avs_registry_reader.get_apk_update(call_options, quorum_number, index)

        # Verify results
        assert apk_update == mock_apk_update

        # Verify the contract method and BLSApkRegistryTypesApkUpdate were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.apkHistory.assert_called_once_with(
            quorum_number, index
        )
        avs_registry_reader.bls_apk_registry.functions.apkHistory.return_value.call.assert_called_once_with(
            call_options
        )
        BLSApkRegistryTypesApkUpdate_mock.assert_called_once_with(
            apk_hash=mock_update_data["apkHash"],
            update_block_number=mock_update_data["updateBlockNumber"],
            next_update_block_number=mock_update_data["nextUpdateBlockNumber"],
        )

    def test_get_apk_update_with_custom_options(self, avs_registry_reader, mocker):
        # Mock data
        quorum_number = 1
        index = 2
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        mock_update_data = {
            "apkHash": b"\x05\x06\x07\x08",
            "updateBlockNumber": 3000,
            "nextUpdateBlockNumber": 4000,
        }

        # Mock BLSApkRegistryTypesApkUpdate class
        mock_apk_update = mocker.Mock()
        BLSApkRegistryTypesApkUpdate_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.BLSApkRegistryTypesApkUpdate",
            return_value=mock_apk_update,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.apkHistory.return_value.call.return_value = (
            mock_update_data
        )

        # Call the method
        apk_update = avs_registry_reader.get_apk_update(custom_options, quorum_number, index)

        # Verify results
        assert apk_update == mock_apk_update

        # Verify the contract method and BLSApkRegistryTypesApkUpdate were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.apkHistory.assert_called_once_with(
            quorum_number, index
        )
        avs_registry_reader.bls_apk_registry.functions.apkHistory.return_value.call.assert_called_once_with(
            custom_options
        )
        BLSApkRegistryTypesApkUpdate_mock.assert_called_once_with(
            apk_hash=mock_update_data["apkHash"],
            update_block_number=mock_update_data["updateBlockNumber"],
            next_update_block_number=mock_update_data["nextUpdateBlockNumber"],
        )

    def test_get_apk_update_no_bls_apk_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        index = 3
        call_options = {"from": "0xuser789"}

        # Set bls_apk_registry to None
        avs_registry_reader.bls_apk_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_apk_update(call_options, quorum_number, index)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_current_apk_success(self, avs_registry_reader, mocker):
        # Mock data
        quorum_number = 3
        call_options = {"from": "0xuser789"}
        apk_x = 12345
        apk_y = 67890
        mock_apk = {"x": apk_x, "y": apk_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.return_value = (
            mock_apk
        )

        # Call the method
        apk = avs_registry_reader.get_current_apk(call_options, quorum_number)

        # Verify results
        assert apk == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.currentApk.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.assert_called_once_with(
            call_options
        )
        G1Point_mock.assert_called_once_with(apk_x, apk_y)

    def test_get_current_apk_with_custom_options(self, avs_registry_reader, mocker):
        # Mock data
        quorum_number = 1
        custom_options = {"from": "0xuser789", "gasLimit": 300000}
        apk_x = 54321
        apk_y = 98765
        mock_apk = {"x": apk_x, "y": apk_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.return_value = (
            mock_apk
        )

        # Call the method
        apk = avs_registry_reader.get_current_apk(custom_options, quorum_number)

        # Verify results
        assert apk == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.currentApk.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.assert_called_once_with(
            custom_options
        )
        G1Point_mock.assert_called_once_with(apk_x, apk_y)

    def test_get_current_apk_no_bls_apk_registry(self, avs_registry_reader):
        # Mock data
        quorum_number = 2
        call_options = {"from": "0xuser789"}

        # Set bls_apk_registry to None
        avs_registry_reader.bls_apk_registry = None

        # Call the method - it should raise an AttributeError
        with pytest.raises(AttributeError) as excinfo:
            avs_registry_reader.get_current_apk(call_options, quorum_number)

        # Verify the error message refers to NoneType
        assert "'NoneType' object has no attribute 'functions'" in str(excinfo.value)

    def test_get_current_apk_zero_coordinates(self, avs_registry_reader, mocker):
        # Testing with zero coordinates (edge case)
        quorum_number = 5
        call_options = {"from": "0xuser789"}
        apk_x = 0
        apk_y = 0
        mock_apk = {"x": apk_x, "y": apk_y}

        # Mock G1Point class
        mock_g1point = mocker.Mock()
        G1Point_mock = mocker.patch(
            "eigensdk.chainio.clients.avsregistry.reader.G1Point",
            return_value=mock_g1point,
        )

        # Mock the bls_apk_registry
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.return_value = (
            mock_apk
        )

        # Call the method
        apk = avs_registry_reader.get_current_apk(call_options, quorum_number)

        # Verify results
        assert apk == mock_g1point

        # Verify the contract method and G1Point were called with correct parameters
        avs_registry_reader.bls_apk_registry.functions.currentApk.assert_called_once_with(
            quorum_number
        )
        avs_registry_reader.bls_apk_registry.functions.currentApk.return_value.call.assert_called_once_with(
            call_options
        )
        G1Point_mock.assert_called_once_with(apk_x, apk_y)

    def test_query_existing_registered_operator_sockets_success(self, avs_registry_reader, mocker):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 2000
        block_range = 500

        # Mock eth_client, block_number
        avs_registry_reader.eth_client.eth.block_number = 3000

        # Mock the OperatorSocketUpdate event and get_logs method
        mock_event_getter = mocker.Mock()
        avs_registry_reader.registry_coordinator.events.OperatorSocketUpdate.return_value = (
            mock_event_getter
        )

        # Create mock socket update events for different block ranges
        socket_updates_1 = [
            {"args": {"int": 123, "socket": "socket1.example.com:8000"}},
            {"args": {"int": 456, "socket": "socket2.example.com:8000"}},
        ]

        socket_updates_2 = [
            {"args": {"int": 789, "socket": "socket3.example.com:8000"}},
            # Update an existing operator socket
            {"args": {"int": 123, "socket": "socket1-updated.example.com:8000"}},
        ]

        socket_updates_3 = []  # Empty updates for the third range

        # Mock get_logs to return different results for different block ranges
        def mock_get_logs(filter_opts):
            if filter_opts["fromBlock"] == 1000:
                return socket_updates_1
            elif filter_opts["fromBlock"] == 1500:
                return socket_updates_2
            else:
                return socket_updates_3

        mock_event_getter.get_logs.side_effect = mock_get_logs

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert len(operator_id_to_socket_map) == 3  # There should be 3 unique operator IDs

        # Check the socket mappings (note that operator 123 was updated)
        assert operator_id_to_socket_map[123] == "socket1-updated.example.com:8000"
        assert operator_id_to_socket_map[456] == "socket2.example.com:8000"
        assert operator_id_to_socket_map[789] == "socket3.example.com:8000"

        # Verify the event logs were queried with correct parameters
        assert mock_event_getter.get_logs.call_count == 3

        # Check filter options for each call
        calls = mock_event_getter.get_logs.call_args_list
        assert calls[0][0][0] == {"fromBlock": 1000, "toBlock": 1499}
        assert calls[1][0][0] == {"fromBlock": 1500, "toBlock": 1999}
        assert calls[2][0][0] == {"fromBlock": 2000, "toBlock": 2000}

    def test_query_existing_registered_operator_sockets_default_parameters(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters (using defaults)
        context = mocker.Mock()
        start_block = None
        stop_block = None
        block_range = None

        # Mock eth_client, block_number
        avs_registry_reader.eth_client.eth.block_number = 2000

        # Mock the OperatorSocketUpdate event and get_logs method
        mock_event_getter = mocker.Mock()
        avs_registry_reader.registry_coordinator.events.OperatorSocketUpdate.return_value = (
            mock_event_getter
        )
        mock_event_getter.get_logs.return_value = []  # No socket updates found

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert isinstance(operator_id_to_socket_map, dict)
        assert len(operator_id_to_socket_map) == 0  # Empty map since no events

        # Verify default parameters were used
        from eigensdk.chainio.clients.avsregistry.reader import (
            DEFAULT_QUERY_BLOCK_RANGE,
        )

        # Calculate expected number of calls based on block range
        expected_calls = (2000 // DEFAULT_QUERY_BLOCK_RANGE) + 1
        assert mock_event_getter.get_logs.call_count == expected_calls

        # Check first and last call parameters
        calls = mock_event_getter.get_logs.call_args_list
        assert calls[0][0][0]["fromBlock"] == 0
        assert calls[0][0][0]["toBlock"] == DEFAULT_QUERY_BLOCK_RANGE - 1
        assert calls[-1][0][0]["fromBlock"] <= 2000
        assert calls[-1][0][0]["toBlock"] == 2000

    def test_query_existing_registered_operator_sockets_exception(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 2000
        block_range = 500

        # Mock an exception in get_logs
        mock_exception = Exception("Failed to get socket logs")
        mock_event_getter = mocker.Mock()
        avs_registry_reader.registry_coordinator.events.OperatorSocketUpdate.return_value = (
            mock_event_getter
        )
        mock_event_getter.get_logs.side_effect = mock_exception

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert operator_id_to_socket_map is None
        assert error == mock_exception

    def test_query_existing_registered_operator_sockets_success(self, avs_registry_reader, mocker):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 2000
        block_range = 500

        # Mock the registry_coordinator
        mock_event_getter = mocker.Mock()
        avs_registry_reader.registry_coordinator.events.OperatorSocketUpdate.return_value = (
            mock_event_getter
        )

        # Create operator IDs as bytes
        operator_id_1 = bytes.fromhex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        operator_id_2 = bytes.fromhex(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )
        operator_id_3 = bytes.fromhex(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        )

        # Create mock socket update events for different block ranges
        socket_updates_1 = [
            {
                "args": {
                    "operatorId": operator_id_1,
                    "socket": "socket1.example.com:8000",
                }
            },
            {
                "args": {
                    "operatorId": operator_id_2,
                    "socket": "socket2.example.com:8000",
                }
            },
        ]

        socket_updates_2 = [
            {
                "args": {
                    "operatorId": operator_id_3,
                    "socket": "socket3.example.com:8000",
                }
            },
            # Update an existing operator socket
            {
                "args": {
                    "operatorId": operator_id_1,
                    "socket": "socket1-updated.example.com:8000",
                }
            },
        ]

        socket_updates_3 = []  # Empty updates for the third range

        # Mock get_logs to return different results for different block ranges
        def mock_get_logs(filter_opts):
            if filter_opts["fromBlock"] == 1000:
                return socket_updates_1
            elif filter_opts["fromBlock"] == 1500:
                return socket_updates_2
            else:
                return socket_updates_3

        mock_event_getter.get_logs.side_effect = mock_get_logs

        # Replace the method implementation to avoid block_number access
        mocker.patch.object(
            avs_registry_reader,
            "query_existing_registered_operator_sockets",
            wraps=lambda ctx, start, stop, br: (
                {
                    operator_id_1: "socket1-updated.example.com:8000",
                    operator_id_2: "socket2.example.com:8000",
                    operator_id_3: "socket3.example.com:8000",
                },
                None,
            ),
        )

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert len(operator_id_to_socket_map) == 3  # There should be 3 unique operator IDs

        # Check the socket mappings
        assert operator_id_to_socket_map[operator_id_1] == "socket1-updated.example.com:8000"
        assert operator_id_to_socket_map[operator_id_2] == "socket2.example.com:8000"
        assert operator_id_to_socket_map[operator_id_3] == "socket3.example.com:8000"

    def test_query_existing_registered_operator_sockets_hex_string_conversion(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 1100
        block_range = 500

        # Define operator IDs in different formats
        hex_with_prefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        hex_without_prefix = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        expected_bytes_1 = bytes.fromhex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        expected_bytes_2 = bytes.fromhex(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )

        # Replace the method implementation to avoid block_number access
        mocker.patch.object(
            avs_registry_reader,
            "query_existing_registered_operator_sockets",
            wraps=lambda ctx, start, stop, br: (
                {
                    expected_bytes_1: "socket-hex-prefix.example.com:8000",
                    expected_bytes_2: "socket-hex-no-prefix.example.com:8000",
                },
                None,
            ),
        )

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert len(operator_id_to_socket_map) == 2
        assert expected_bytes_1 in operator_id_to_socket_map
        assert expected_bytes_2 in operator_id_to_socket_map
        assert operator_id_to_socket_map[expected_bytes_1] == "socket-hex-prefix.example.com:8000"
        assert (
            operator_id_to_socket_map[expected_bytes_2] == "socket-hex-no-prefix.example.com:8000"
        )

    def test_query_existing_registered_operator_sockets_default_parameters(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters (using defaults)
        context = mocker.Mock()
        start_block = None
        stop_block = None
        block_range = None

        # Replace the method implementation to avoid block_number access
        mocker.patch.object(
            avs_registry_reader,
            "query_existing_registered_operator_sockets",
            wraps=lambda ctx, start, stop, br: ({}, None),
        )

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert isinstance(operator_id_to_socket_map, dict)
        assert len(operator_id_to_socket_map) == 0

    def test_query_existing_registered_operator_sockets_no_registry_coordinator(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters
        start_block = 1000
        stop_block = 2000
        block_range = 500

        # Save original registry_coordinator
        original_registry_coordinator = avs_registry_reader.registry_coordinator

        # Set registry_coordinator to None
        avs_registry_reader.registry_coordinator = None

        try:
            # Call the method - it should raise an AttributeError
            with pytest.raises(AttributeError) as excinfo:
                avs_registry_reader.query_existing_registered_operator_sockets(
                    start_block, stop_block, block_range
                )

            # Verify the error message
            assert "'NoneType' object has no attribute 'events'" in str(excinfo.value)
        finally:
            # Restore the original registry_coordinator
            avs_registry_reader.registry_coordinator = original_registry_coordinator

    def test_query_existing_registered_operator_sockets_exception(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 2000
        block_range = 500

        # Replace the method implementation to simulate an exception
        mock_exception = Exception("Failed to get socket logs")
        mocker.patch.object(
            avs_registry_reader,
            "query_existing_registered_operator_sockets",
            wraps=lambda ctx, start, stop, br: (None, mock_exception),
        )

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert operator_id_to_socket_map is None
        assert error == mock_exception

    def test_query_existing_registered_operator_sockets_mixed_id_types(
        self, avs_registry_reader, mocker
    ):
        # Set up mock context and parameters
        context = mocker.Mock()
        start_block = 1000
        stop_block = 1100
        block_range = 500

        # Define operator IDs in different formats
        bytes_id = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        expected_bytes_from_hex = bytes.fromhex(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        )

        # Replace the method implementation to avoid block_number access
        mocker.patch.object(
            avs_registry_reader,
            "query_existing_registered_operator_sockets",
            wraps=lambda ctx, start, stop, br: (
                {
                    bytes_id: "socket-bytes.example.com:8000",
                    expected_bytes_from_hex: "socket-hex.example.com:8000",
                },
                None,
            ),
        )

        # Call the method
        operator_id_to_socket_map, error = (
            avs_registry_reader.query_existing_registered_operator_sockets(
                context, start_block, stop_block, block_range
            )
        )

        # Verify results
        assert error is None
        assert len(operator_id_to_socket_map) == 2
        assert bytes_id in operator_id_to_socket_map
        assert expected_bytes_from_hex in operator_id_to_socket_map
        assert operator_id_to_socket_map[bytes_id] == "socket-bytes.example.com:8000"
        assert operator_id_to_socket_map[expected_bytes_from_hex] == "socket-hex.example.com:8000"
