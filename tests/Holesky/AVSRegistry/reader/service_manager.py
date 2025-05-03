from dataclasses import dataclass
from typing import Dict, Any, List
from tests.builder import holesky_avs_registry_reader
from eth_typing import Address


# Utility function to remove duplicate strategies
def remove_duplicate_strategies(strategies: List[str]) -> List[str]:
    # Convert to a set to remove duplicates, then back to a list
    return list(set(strategies))


# def test_get_restakeable_strategies():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     return holesky_avs_registry_reader.get_restakeable_strategies(
#         call_options=call_options
#     )


# def test_get_operator_restaked_strategies():
#     # Sample call options (empty dictionary is fine for most calls)
#     call_options = {}

#     # Sample operator address
#     operator = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"

#     return holesky_avs_registry_reader.get_operator_restaked_strategies(
#         call_options=call_options,
#         operator=operator
#     )
