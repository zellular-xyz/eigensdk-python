from builder import el_reader
import os
from dotenv import load_dotenv
from typing import List, Dict, Any, Tuple, Optional
from web3 import Web3
import time

# Load environment variables
load_dotenv()

def test_get_allocatable_magnitude():
    # Get addresses from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    strategy_addr = os.getenv("STRATEGY_ADDR")
    
    # Get the allocatable magnitude for the operator and strategy
    magnitude = el_reader.get_allocatable_magnitude(
        operator_addr=operator_addr,
        strategy_addr=strategy_addr
    )
    
    # Basic test - just verify we get a non-negative number
    assert magnitude >= 0, "Allocatable magnitude should be non-negative"
    
    # Print the result for debugging
    print(f"Allocatable magnitude for operator {operator_addr} and strategy {strategy_addr}: {magnitude}")


def test_get_max_magnitudes():
    # Get addresses from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    strategy_addr = os.getenv("STRATEGY_ADDR")
    
    # Create a list of strategy addresses (using the same strategy for simplicity)
    strategy_addrs = [strategy_addr]
    
    # Get the max magnitudes for the operator and strategies
    magnitudes = el_reader.get_max_magnitudes(
        operator_addr=operator_addr,
        strategy_addrs=strategy_addrs
    )
    
    # Verify we get a list with the expected length
    assert isinstance(magnitudes, list), "Result should be a list"
    assert len(magnitudes) == len(strategy_addrs), "Result list should match input list length"
    
    # Verify all magnitudes are non-negative
    for magnitude in magnitudes:
        assert magnitude >= 0, "Max magnitude should be non-negative"
    
    # Print the results for debugging
    for i, magnitude in enumerate(magnitudes):
        print(f"Max magnitude for operator {operator_addr} and strategy {strategy_addrs[i]}: {magnitude}")


def test_get_allocation_info():
    # Get addresses from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    strategy_addr = os.getenv("STRATEGY_ADDR")
    
    # Get the allocation info for the operator and strategy
    allocation_info = el_reader.get_allocation_info(
        operator_addr=operator_addr,
        strategy_addr=strategy_addr
    )
    
    # Verify we get a list
    assert isinstance(allocation_info, list), "Result should be a list"
    
    # Check each allocation entry if list is not empty
    if allocation_info:
        for entry in allocation_info:
            # Verify the structure of each entry
            assert isinstance(entry, dict), "Each entry should be a dictionary"
            assert "OperatorSetId" in entry, "Entry should have OperatorSetId field"
            assert "AvsAddress" in entry, "Entry should have AvsAddress field"
            assert "CurrentMagnitude" in entry, "Entry should have CurrentMagnitude field"
            assert "PendingDiff" in entry, "Entry should have PendingDiff field"
            assert "EffectBlock" in entry, "Entry should have EffectBlock field"
            
            # Verify types of values
            assert isinstance(entry["CurrentMagnitude"], int), "CurrentMagnitude should be an integer"
            assert isinstance(entry["PendingDiff"], int), "PendingDiff should be an integer"
            assert isinstance(entry["EffectBlock"], int), "EffectBlock should be an integer"
    
    # Print the results for debugging
    print(f"Allocation info for operator {operator_addr} and strategy {strategy_addr}:")
    for entry in allocation_info:
        print(f"  OperatorSetId: {entry['OperatorSetId']}")
        print(f"  AvsAddress: {entry['AvsAddress']}")
        print(f"  CurrentMagnitude: {entry['CurrentMagnitude']}")
        print(f"  PendingDiff: {entry['PendingDiff']}")
        print(f"  EffectBlock: {entry['EffectBlock']}")
        print("-----")


def test_get_operator_sets_for_operator():
    # Get operator address from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    
    try:
        # Get the operator sets for the operator
        operator_sets = el_reader.get_operator_sets_for_operator(
            operator_addr=operator_addr
        )
        
        # Verify we get a list
        assert isinstance(operator_sets, list), "Result should be a list"
        
        # Check each set entry if list is not empty
        if operator_sets:
            for entry in operator_sets:
                # Verify the structure of each entry
                assert isinstance(entry, dict), "Each entry should be a dictionary"
                assert "Id" in entry, "Entry should have Id field"
                assert "AvsAddress" in entry, "Entry should have AvsAddress field"
                
                # Verify types of values (assuming Id and AvsAddress are strings or similar types)
                assert entry["Id"] is not None, "Id should not be None"
                assert entry["AvsAddress"] is not None, "AvsAddress should not be None"
        
        # Print the results for debugging
        print(f"Operator sets for operator {operator_addr}:")
        for entry in operator_sets:
            print(f"  Id: {entry['Id']}")
            print(f"  AvsAddress: {entry['AvsAddress']}")
            print("-----")
            
    except Exception as e:
        print(f"Error calling get_operator_sets_for_operator: {e}")
        # Additional diagnostics
        print("This could indicate the contract is not deployed, addresses are incorrect, or RPC connection issues")


def test_get_allocation_delay():
    # Get operator address from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    
    # Get the allocation delay for the operator
    delay = el_reader.get_allocation_delay(
        operator_addr=operator_addr
    )
    
    # Verify delay is a non-negative integer
    assert isinstance(delay, int), "Allocation delay should be an integer"
    assert delay >= 0, "Allocation delay should be non-negative"
    
    # Print the result for debugging
    print(f"Allocation delay for operator {operator_addr}: {delay}")


def test_get_registered_sets():
    # Get operator address from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    
    # Get the registered sets for the operator
    registered_sets = el_reader.get_registered_sets(
        operator_addr=operator_addr
    )
    
    # Verify we get a list
    assert isinstance(registered_sets, list), "Result should be a list"
    
    # Check each set entry if list is not empty
    if registered_sets:
        for entry in registered_sets:
            # Verify the structure of each entry
            assert isinstance(entry, dict), "Each entry should be a dictionary"
            assert "Id" in entry, "Entry should have Id field"
            assert "Avs" in entry, "Entry should have Avs field"
            
            # Verify values are not None
            assert entry["Id"] is not None, "Id should not be None"
            assert entry["Avs"] is not None, "Avs should not be None"
    
    # Print the results for debugging
    print(f"Registered sets for operator {operator_addr}:")
    for entry in registered_sets:
        print(f"  Id: {entry['Id']}")
        print(f"  Avs: {entry['Avs']}")
        print("-----")


def test_is_operator_registered_with_operator_set():
    # Get operator address from environment variables
    operator_addr = os.getenv("SENDER_ADDRESS")
    avs_addr = os.getenv("AVS_DIRECTORY_ADDR")  # Using AVS directory address as an example
    
    # First, get all registered sets for the operator
    registered_sets = el_reader.get_registered_sets(
        operator_addr=operator_addr
    )
    
    # Create test cases
    test_cases = []
    
    # Case 1: If registered sets exist, test with the first one (should return True)
    if registered_sets:
        test_cases.append({
            "operator_set": registered_sets[0],
            "expected_result": True,
            "description": "Existing registered set"
        })
    
    # Case 2: Test with a likely non-existent set (should return False)
    test_cases.append({
        "operator_set": {"Id": 999999, "Avs": avs_addr},
        "expected_result": False,
        "description": "Non-existent set ID"
    })
    
    # Case 3: Test with a valid ID but wrong AVS address (should return False)
    if registered_sets:
        invalid_set = registered_sets[0].copy()
        invalid_set["Avs"] = "0x" + "1" * 40  # Create an invalid address
        test_cases.append({
            "operator_set": invalid_set,
            "expected_result": False,
            "description": "Valid ID but wrong AVS address"
        })
    
    # Run the tests
    for case in test_cases:
        operator_set = case["operator_set"]
        expected = case["expected_result"]
        
        # Check if the operator is registered with the set
        is_registered = el_reader.is_operator_registered_with_operator_set(
            operator_addr=operator_addr,
            operator_set=operator_set
        )
        
        # Verify the result matches the expected value
        assert is_registered == expected, f"For {case['description']}, expected {expected} but got {is_registered}"
        
        # Print the result for debugging
        print(f"Test case: {case['description']}")
        print(f"  Operator: {operator_addr}")
        print(f"  Operator Set: {operator_set}")
        print(f"  Is Registered: {is_registered}")
        print("-----")


