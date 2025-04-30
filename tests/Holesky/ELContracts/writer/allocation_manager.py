from tests.builder import holesky_el_writer
from eigensdk.crypto.bls.attestation import BLSKeyPair, new_private_key
from eth_typing import Address
import time



def test_modify_allocations():
    registry_coordinator_addr = "0x8771E1aE4a8D98AEFdbcefFe8940F14d83891B7f"
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    
    private_key = new_private_key()
    bls_key_pair = BLSKeyPair(private_key)
    
    register_request = {
        "operator_address": operator_address,
        "avs_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "operator_set_ids": [1],
        "socket": "localhost:9000",
        "bls_key_pair": bls_key_pair,
        "wait_for_receipt": True
    }
    
    print("Registering operator...")
    register_tx = holesky_el_writer.register_for_operator_sets(
        registry_coordinator_addr=registry_coordinator_addr,
        request=register_request
    )
    print(f"Registration transaction: {register_tx}")
    
    time.sleep(10)
    
    allocations = [
        {
            "operatorSet": {
                "id": 1,
                "avs": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
                "quorumNumber": 1
            },
            "strategies": ["0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"],
            "newMagnitudes": [100]
        }
    ]
    
    return holesky_el_writer.modify_allocations(
        operator_address=operator_address,
        allocations=allocations,
        wait_for_receipt=True
    )



def test_clear_deallocation_queue():
    # Sample operator address
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    
    # Sample strategy addresses
    strategies = [
        "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "0xe03D546ADa84B5624b50aA22Ff8B87baDEf44ee2"
    ]
    
    # Numbers to clear for each strategy
    nums_to_clear = [1, 2]
    
    # Set wait_for_receipt to False for testing to avoid waiting for transaction confirmation
    return holesky_el_writer.clear_deallocation_queue(
        operator_address=operator_address,
        strategies=strategies,
        nums_to_clear=nums_to_clear,
        wait_for_receipt=False
    )



def test_set_allocation_delay():
    operator_address = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    delay = 86400  # 1 day in seconds
    return holesky_el_writer.set_allocation_delay(
        operator_address=operator_address,
        delay=delay,
        wait_for_receipt=False
    )


def test_deregister_from_operator_sets():
    # Sample operator address
    operator = "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"
    
    # Sample request dictionary with required fields
    request = {
        "avs_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "operator_set_ids": [1, 2],  # Sample operator set IDs
        "wait_for_receipt": False    # Avoid waiting for transaction confirmation
    }
    
    return holesky_el_writer.deregister_from_operator_sets(
        operator=operator,
        request=request
    )


def test_register_for_operator_sets():
    registry_coordinator_addr = "0x8771E1aE4a8D98AEFdbcefFe8940F14d83891B7f"
    private_key = new_private_key()
    bls_key_pair = BLSKeyPair(private_key)
    
    request = {
        "operator_address": "0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792",
        "avs_address": "0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e",
        "operator_set_ids": [1, 2],  # Sample operator set IDs
        "socket": "localhost:9000",  # Sample socket address
        "bls_key_pair": bls_key_pair,
        "wait_for_receipt": False    # Avoid waiting for transaction confirmation
    }
    
    return holesky_el_writer.register_for_operator_sets(
        registry_coordinator_addr=registry_coordinator_addr,
        request=request
    )

