
from dataclasses import dataclass
from typing import Dict, Any, List
from tests.builder import holesky_avs_registry_writer
from eth_typing import Address

def test_set_slashable_stake_lookahead():
    # Sample quorum number
    quorum_number = 0  # Set lookahead for quorum 0
    
    # Sample look ahead period (number of blocks)
    look_ahead_period = 200
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_slashable_stake_lookahead(
        quorum_number=quorum_number,
        look_ahead_period=look_ahead_period,
        wait_for_receipt=False
    )

def test_set_minimum_stake_for_quorum():
    # Sample quorum number
    quorum_number = 0  # Set minimum stake for quorum 0
    
    # Sample minimum stake (e.g., 50 tokens with 18 decimals)
    minimum_stake = 50 * 10**18
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.set_minimum_stake_for_quorum(
        quorum_number=quorum_number,
        minimum_stake=minimum_stake,
        wait_for_receipt=False
    )

def test_modify_strategy_params():
    # Sample quorum number
    quorum_number = 0  # Modify strategies for quorum 0
    
    # Sample strategy indices to modify
    strategy_indices = [0, 1]  # Modify the first two strategies
    
    # Sample new multipliers for each strategy
    multipliers = [7500, 2500]  # 75% and 25% weight multipliers
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.modify_strategy_params(
        quorum_number=quorum_number,
        strategy_indices=strategy_indices,
        multipliers=multipliers,
        wait_for_receipt=False
    )

def test_add_strategies():
    # Sample quorum number
    quorum_number = 0  # Add strategies to quorum 0
    
    # Sample strategy parameters to add
    strategy_params = [
        {
            "strategy": "0x6B175474E89094C44Da98b954EedeAC495271d0F",  # Sample strategy contract address
            "multiplier": 8000  # 80% weight multiplier
        },
        {
            "strategy": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # Sample strategy contract address
            "multiplier": 2000  # 20% weight multiplier
        }
    ]
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.add_strategies(
        quorum_number=quorum_number,
        strategy_params=strategy_params,
        wait_for_receipt=False
    )

def test_remove_strategies():
    # Sample quorum number
    quorum_number = 0  # Remove strategies from quorum 0
    
    # Sample indices of strategies to remove
    indices_to_remove = [1, 3]  # Remove the 2nd and 4th strategies (zero-indexed)
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_avs_registry_writer.remove_strategies(
        quorum_number=quorum_number,
        indices_to_remove=indices_to_remove,
        wait_for_receipt=False
    )
