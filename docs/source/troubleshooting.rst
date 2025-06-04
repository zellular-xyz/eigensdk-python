.. _troubleshooting:

Troubleshooting Guide
====================

This guide covers common issues and their solutions when working with EigenSDK-Python.

Installation Issues
~~~~~~~~~~~~~~~~~~~

MCL Library Installation Problems
---------------------------------

**Problem**: ``ImportError: cannot find MCL library``

**Solutions**:

.. code-block:: shell

    # Ubuntu/Debian
    $ sudo apt update
    $ sudo apt install libgmp3-dev build-essential cmake

    # macOS
    $ brew install gmp cmake

    # If MCL is installed but not found, set library path
    $ export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

**Problem**: ``cmake not found`` during MCL compilation

**Solution**:

.. code-block:: shell

    # Ubuntu/Debian
    $ sudo apt install cmake

    # macOS
    $ brew install cmake

    # Windows (using vcpkg)
    $ vcpkg install cmake

**Problem**: Permission denied during ``sudo make install``

**Solution**:

.. code-block:: shell

    # Alternative installation to user directory
    $ cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local ..
    $ make install
    $ export LD_LIBRARY_PATH=$HOME/.local/lib:$LD_LIBRARY_PATH

Python Environment Issues
-------------------------

**Problem**: ``ModuleNotFoundError: No module named 'eigensdk'``

**Solutions**:

.. code-block:: shell

    # Verify virtual environment is activated
    $ which python
    $ pip list | grep eigensdk

    # Reinstall if needed
    $ pip uninstall eigensdk-python
    $ pip install git+https://github.com/zellular-xyz/eigensdk-python

**Problem**: Version conflicts with web3.py or other dependencies

**Solution**:

.. code-block:: shell

    # Create fresh environment
    $ python -m venv fresh-env
    $ source fresh-env/bin/activate
    $ pip install git+https://github.com/zellular-xyz/eigensdk-python

Network and RPC Issues
~~~~~~~~~~~~~~~~~~~~~~

Connection Timeouts
-------------------

**Problem**: ``TimeoutError`` or ``ConnectionError`` when connecting to RPC

**Solutions**:

.. code-block:: python

    # Use alternative RPC endpoints
    rpc_endpoints = [
        'https://ethereum-rpc.publicnode.com',
        'https://rpc.ankr.com/eth',
        'https://eth.llamarpc.com',
        'https://ethereum.blockpi.network/v1/rpc/public'
    ]

    # Add timeout and retry logic
    from web3 import Web3
    from web3.middleware import geth_poa_middleware

    w3 = Web3(Web3.HTTPProvider(
        rpc_url, 
        request_kwargs={'timeout': 60}
    ))

**Problem**: ``ValueError: {'code': -32000, 'message': 'execution reverted'}``

**Common Causes & Solutions**:

1. **Insufficient Gas**: Increase gas limit in transactions
2. **Invalid Contract Address**: Verify contract addresses are correct for your network
3. **Operator Not Registered**: Ensure operator is registered before AVS operations
4. **Incorrect Permissions**: Check operator has necessary permissions for the operation

.. code-block:: python

    # Verify contract addresses
    >>> w3.isAddress(contract_address)
    True
    >>> w3.eth.get_code(contract_address)  # Should not be '0x'

Contract Interaction Issues
~~~~~~~~~~~~~~~~~~~~~~~~~~

Invalid Contract Addresses
--------------------------

**Problem**: Contract calls fail with invalid address errors

**Solution**:

.. code-block:: python

    # Verify addresses are valid and contracts are deployed
    from web3 import Web3

    def verify_contract(w3, address, expected_functions=None):
        if not w3.isAddress(address):
            raise ValueError(f"Invalid address: {address}")
        
        code = w3.eth.get_code(address)
        if code == b'':
            raise ValueError(f"No contract at address: {address}")
        
        print(f"✓ Contract verified at {address}")
        return True

    # Example verification
    >>> verify_contract(w3, "0x0BAAc79acD45A023E19345c352d8a7a83C4e5656")

Gas Estimation Failures
-----------------------

**Problem**: Gas estimation fails for transactions

**Solutions**:

.. code-block:: python

    # Manual gas setting
    transaction = {
        'gas': 500000,  # Set manually
        'gasPrice': w3.toWei('20', 'gwei'),
        # ... other params
    }

    # Or use eth_estimateGas with higher multiplier
    estimated_gas = w3.eth.estimate_gas(transaction)
    transaction['gas'] = int(estimated_gas * 1.2)  # 20% buffer

Cryptographic Issues
~~~~~~~~~~~~~~~~~~~

BLS Key Generation Problems
--------------------------

**Problem**: ``RuntimeError`` during key pair generation

**Solutions**:

.. code-block:: python

    # Ensure proper initialization
    from eigensdk.crypto.bls.attestation import KeyPair

    try:
        # Generate with explicit seed for testing
        key_pair = KeyPair.from_string("test_seed_12345", base=16)
        print("✓ Key generation successful")
    except Exception as e:
        print(f"✗ Key generation failed: {e}")
        # Try alternative generation method
        key_pair = KeyPair()

Signature Verification Failures
------------------------------

**Problem**: Valid signatures fail verification

**Common Causes**:

1. **Message Format**: Ensure message bytes are consistent
2. **Key Mismatch**: Verify public/private key correspondence
3. **Hash Domain**: Check if message needs domain separation

.. code-block:: python

    # Debug signature verification
    def debug_signature(key_pair, message):
        signature = key_pair.sign_message(message)
        pub_g2 = key_pair.get_pub_g2()
        
        print(f"Message: {message.hex()}")
        print(f"Signature: {signature.to_json()}")
        print(f"Public Key: {pub_g2.to_json()}")
        
        is_valid = signature.verify(pub_g2, message)
        print(f"Verification: {is_valid}")
        return is_valid

Configuration Issues
~~~~~~~~~~~~~~~~~~~

Missing Required Parameters
---------------------------

**Problem**: ``TypeError`` due to missing configuration parameters

**Solution**:

.. code-block:: python

    # Complete configuration template
    from eigensdk.chainio.clients.builder import BuildAllConfig

    # Get contract addresses from official sources
    config = BuildAllConfig(
        eth_http_url='https://ethereum-rpc.publicnode.com',
        avs_name="your_avs_name",
        
        # Core EigenLayer contracts (Mainnet)
        registry_coordinator_addr='0x...', # Your AVS registry coordinator
        operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
        rewards_coordinator_addr='0x7750d328b314EfFa365A0402CcfD489B80B0adda',
        delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
        allocation_manager_addr='0x3A93c17D806bf74066d7e2c962b7a0F49b97e1Cf',
        
        # AVS-specific contracts
        service_manager_addr='0x...',  # Your service manager
        permission_controller_addr='0x0000000000000000000000000000000000000000',  # Often zero address
    )

Environment Variables Issues
---------------------------

**Problem**: Private keys or RPC URLs not loading from environment

**Solution**:

.. code-block:: python

    import os
    from dotenv import load_dotenv

    # Load environment variables
    load_dotenv()

    # Validate required variables
    required_vars = ['PRIVATE_KEY', 'ETH_RPC_URL']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        raise EnvironmentError(f"Missing environment variables: {missing_vars}")

    private_key = os.getenv('PRIVATE_KEY')
    rpc_url = os.getenv('ETH_RPC_URL')

Performance Issues
~~~~~~~~~~~~~~~~~

Slow RPC Responses
-----------------

**Problem**: Operations taking too long to complete

**Solutions**:

.. code-block:: python

    # Use connection pooling
    from web3 import Web3
    from web3.providers.rpc import HTTPProvider

    provider = HTTPProvider(
        rpc_url,
        request_kwargs={
            'timeout': 30,
            'retries': 3,
        }
    )
    w3 = Web3(provider)

    # Batch RPC calls when possible
    from web3.batch import Batch

    with w3.batch_requests() as batch:
        batch.add(w3.eth.get_block, 'latest')
        batch.add(w3.eth.get_balance, account_address)
        results = batch.execute()

Memory Issues with Large Operations
----------------------------------

**Problem**: ``MemoryError`` when processing many operators

**Solutions**:

.. code-block:: python

    # Process in chunks
    def process_operators_in_chunks(operators, chunk_size=100):
        for i in range(0, len(operators), chunk_size):
            chunk = operators[i:i + chunk_size]
            yield process_chunk(chunk)

    # Use generators for large datasets
    def get_all_operators():
        quorums = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([0])
        for operator in quorums[0]:
            yield operator

Getting Help
~~~~~~~~~~~~

If you're still experiencing issues:

1. **Check the logs**: Enable debug logging to see detailed error information
2. **Verify network status**: Ensure Ethereum network is accessible and synced
3. **Update dependencies**: Make sure you're using compatible versions
4. **Community support**: Join the EigenLayer community channels
5. **GitHub Issues**: Report bugs at the project repository

Debug Logging Setup
------------------

.. code-block:: python

    import logging

    # Enable debug logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger('eigensdk')
    logger.setLevel(logging.DEBUG)

    # This will show detailed information about all operations

Common Error Patterns
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    # Pattern: Check before operations
    def safe_operation(clients, operator_address):
        # 1. Verify operator is registered
        if not clients.el_reader.is_operator_registered(operator_address):
            raise ValueError("Operator not registered with EigenLayer")
        
        # 2. Check AVS registration
        if not clients.avs_registry_reader.is_operator_registered(operator_address):
            raise ValueError("Operator not registered with AVS")
        
        # 3. Proceed with operation
        return perform_operation()

    # Pattern: Retry with exponential backoff
    import time
    import random

    def retry_with_backoff(func, max_retries=3):
        for attempt in range(max_retries):
            try:
                return func()
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time) 