import os
import pytest
from web3 import Web3

# Import the necessary modules
from eigensdk.chainio.clients.builder import ProviderBuilder, SdkClientBuilder
from eigensdk.chainio.txmgr.txmgr import SimpleTxManager
from eigensdk.chainio.clients.avsregistry.reader import AvsRegistryReader

# Set up constants from environment variables
SENDER_ADDRESS = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
PRIVATE_KEY = "f38b6d3c2effbb7afef9aea7ff23a42a09911dec3a75ec12b230c150ec833b52"
ETH_HTTP_URL = "https://holesky.infura.io/v3/889a5bab533a43e993049f577a2c136b"

# Contract addresses - replace with actual addresses on Holesky
# These would typically be replaced with actual deployed contract addresses on Holesky
AVS_REGISTRY_COORDINATOR_ADDRESS = "0x0000000000000000000000000000000000000000"  # Replace with actual address
AVS_STAKE_REGISTRY_ADDRESS = "0x0000000000000000000000000000000000000000"  # Replace with actual address

# Test fixtures
@pytest.fixture
def web3():
    """Initialize Web3 provider."""
    provider_builder = ProviderBuilder()
    provider = provider_builder.build_http_provider(ETH_HTTP_URL)
    return Web3(provider)

@pytest.fixture
def tx_manager(web3):
    """Initialize transaction manager."""
    tx_mgr = SimpleTxManager(web3, SENDER_ADDRESS, PRIVATE_KEY)
    return tx_mgr

@pytest.fixture
def avs_registry_reader(web3, tx_manager):
    """Initialize AVS Registry Reader client."""
    sdk_client_builder = SdkClientBuilder(web3, SENDER_ADDRESS, tx_manager)
    avs_registry_reader = sdk_client_builder.build_avs_registry_reader(
        AVS_REGISTRY_COORDINATOR_ADDRESS
    )
    return avs_registry_reader

# Test StakeRegistry read functions
def test_get_minimum_stake_for_quorum(avs_registry_reader):
    """Test getting minimum stake for a specific quorum."""
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    minimum_stake = avs_registry_reader.get_minimum_stake_for_quorum({}, quorum_number)
    
    # Validate result
    assert minimum_stake is not None, "Minimum stake should not be None"
    print(f"Minimum stake for quorum {quorum_number}: {minimum_stake}")

def test_get_stake_type_per_quorum(avs_registry_reader):
    """Test getting stake type for a specific quorum."""
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    stake_type = avs_registry_reader.get_stake_type_per_quorum({}, quorum_number)
    
    # Validate result
    assert stake_type is not None, "Stake type should not be None"
    print(f"Stake type for quorum {quorum_number}: {stake_type}")

def test_get_current_total_stake(avs_registry_reader):
    """Test getting current total stake for a specific quorum."""
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    total_stake = avs_registry_reader.get_current_total_stake({}, quorum_number)
    
    # Validate result
    assert total_stake is not None, "Total stake should not be None"
    print(f"Current total stake for quorum {quorum_number}: {total_stake}")

def test_get_stake_at_block_number(avs_registry_reader, web3):
    """Test getting stake for an operator at a specific block number."""
    operator_id = 1  # Replace with an actual operator ID
    quorum_number = 0  # Replace with an actual quorum number
    block_number = web3.eth.block_number - 10  # Use a block 10 blocks ago
    
    # Execute the call
    stake = avs_registry_reader.get_stake_at_block_number({}, operator_id, quorum_number, block_number)
    
    # Validate result
    assert stake is not None, "Stake should not be None"
    print(f"Stake for operator {operator_id} in quorum {quorum_number} at block {block_number}: {stake}")

def test_get_strategy_params_at_index(avs_registry_reader):
    """Test getting strategy parameters for a specific quorum at a specific index."""
    quorum_number = 0  # Replace with an actual quorum number
    index = 0  # First strategy
    
    # Execute the call
    strategy_params = avs_registry_reader.get_strategy_params_at_index({}, quorum_number, index)
    
    # Validate result
    assert strategy_params is not None, "Strategy parameters should not be None"
    print(f"Strategy parameters for quorum {quorum_number} at index {index}:")
    print(f"Strategy address: {strategy_params.strategy}")
    print(f"Multiplier: {strategy_params.multiplier}")

def test_is_operator_set_quorum(avs_registry_reader):
    """Test checking if a quorum is an operator set quorum."""
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    is_operator_set = avs_registry_reader.is_operator_set_quorum({}, quorum_number)
    
    # Validate result
    assert is_operator_set is not None, "Result should not be None"
    print(f"Is quorum {quorum_number} an operator set quorum: {is_operator_set}")

def test_get_stake_history_length(avs_registry_reader):
    """Test getting the length of stake history for an operator in a quorum."""
    operator_id = 1  # Replace with an actual operator ID
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    history_length = avs_registry_reader.get_stake_history_length({}, operator_id, quorum_number)
    
    # Validate result
    assert history_length is not None, "History length should not be None"
    print(f"Stake history length for operator {operator_id} in quorum {quorum_number}: {history_length}")

def test_get_stake_update_index_at_block_number(avs_registry_reader, web3):
    """Test getting stake update index at a specific block number."""
    operator_id = 1  # Replace with an actual operator ID
    quorum_number = 0  # Replace with an actual quorum number
    block_number = web3.eth.block_number - 10  # Use a block 10 blocks ago
    
    # Execute the call
    index = avs_registry_reader.get_stake_update_index_at_block_number(
        {}, operator_id, quorum_number, block_number
    )
    
    # Validate result
    assert index is not None, "Index should not be None"
    print(f"Stake update index for operator {operator_id} in quorum {quorum_number} at block {block_number}: {index}")

def test_get_total_stake_history_length(avs_registry_reader):
    """Test getting the length of total stake history for a quorum."""
    quorum_number = 0  # Replace with an actual quorum number
    
    # Execute the call
    history_length = avs_registry_reader.get_total_stake_history_length({}, quorum_number)
    
    # Validate result
    assert history_length is not None, "History length should not be None"
    print(f"Total stake history length for quorum {quorum_number}: {history_length}")

def test_get_total_stake_indices_at_block_number(avs_registry_reader, web3):
    """Test getting total stake indices at a specific block number."""
    quorum_numbers = [0]  # Replace with actual quorum numbers
    block_number = web3.eth.block_number - 10  # Use a block 10 blocks ago
    
    # Execute the call
    indices = avs_registry_reader.get_total_stake_indices_at_block_number(
        {}, quorum_numbers, block_number
    )
    
    # Validate result
    assert indices is not None, "Indices should not be None"
    print(f"Total stake indices for quorums {quorum_numbers} at block {block_number}: {indices}") 