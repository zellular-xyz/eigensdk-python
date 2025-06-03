.. _quickstart:

Quickstart
==========

**Requirements**
- Python 3.8 or higher (3.9+ recommended)
- Ubuntu 18.04+ / macOS 10.15+ / Windows 10+
- Git for installation from source

Dependencies
------------

The installation requires the [MCL](https://github.com/herumi/mcl) native package. To install MCL, execute the following commands:

**Ubuntu/Debian:**

.. code-block:: shell

    $ sudo apt update
    $ sudo apt install libgmp3-dev build-essential cmake git
    $ wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
    $ unzip v1.93.zip
    $ cd mcl-1.93
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make -j$(nproc)
    $ sudo make install
    $ sudo ldconfig

**macOS:**

.. code-block:: shell

    $ brew install gmp cmake
    $ wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
    $ unzip v1.93.zip
    $ cd mcl-1.93
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make -j$(sysctl -n hw.ncpu)
    $ sudo make install

**Windows (WSL2 recommended):**

For Windows users, we recommend using WSL2 with Ubuntu and following the Ubuntu instructions above.

Installation
------------

.. _setup_environment:

**Option 1: Manual Installation**

Install `eigensdk-python` using ``pip``. It is recommended to perform this installation within a virtual environment:

.. code-block:: shell

    $ python -m venv eigensdk-env
    $ source eigensdk-env/bin/activate  # On Windows: eigensdk-env\Scripts\activate
    $ pip install --upgrade pip setuptools wheel
    $ pip install git+https://github.com/abramsymons/eigensdk-python

**Option 2: Docker Setup (Recommended)**

A complete Docker-based environment is provided, featuring Python 3.12, pre-installed MCL library, Foundry, EigenLayer contracts, and development tools:

.. code-block:: shell

    $ git clone https://github.com/abramsymons/eigensdk-python
    $ cd eigensdk-python
    $ make build
    $ make test

**Option 3: Development Installation**

For contributing to the SDK or advanced usage:

.. code-block:: shell

    $ git clone https://github.com/abramsymons/eigensdk-python
    $ cd eigensdk-python
    $ python -m venv venv
    $ source venv/bin/activate
    $ pip install -e ".[dev]"  # Install in editable mode with dev dependencies

Verification
-----------

Verify your installation by testing the basic imports and crypto functionality:

.. code-block:: python

    >>> from eigensdk.crypto.bls.attestation import KeyPair
    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> 
    >>> # Test BLS key generation
    >>> key_pair = KeyPair()
    >>> print("✅ BLS key generation successful")
    >>> 
    >>> # Test basic configuration
    >>> config = BuildAllConfig(
    ...     eth_http_url='https://ethereum-rpc.publicnode.com',
    ...     avs_name="test",
    ...     registry_coordinator_addr='0x0BAAc79acD45A023E19345c352d8a7a83C4e5656',
    ...     operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
    ...     rewards_coordinator_addr='0x7750d328b314EfFa365A0402CcfD489B80B0adda',
    ...     permission_controller_addr='0x0000000000000000000000000000000000000000',
    ...     service_manager_addr='0x870679E138bCdf293b7ff14dD44b70FC97e12fc0',
    ...     allocation_manager_addr='0x3A93c17D806bf74066d7e2c962b7a0F49b97e1Cf',
    ...     delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
    ... )
    >>> print("✅ Configuration created successfully")

Migration from EigenSDK-Go
-------------------------

If you're migrating from the Go SDK, here are the key differences and migration tips:

**Key Differences:**

1. **Package Structure**: Python uses ``eigensdk.chainio`` and ``eigensdk.crypto`` instead of Go's nested package structure
2. **Configuration**: Python uses ``BuildAllConfig`` class instead of Go's struct initialization
3. **Error Handling**: Python uses exceptions instead of Go's error return values
4. **Type System**: Python uses dataclasses and type hints instead of Go structs

**Common Migration Patterns:**

.. code-block:: python

    # Go: config := &BuildAllConfig{...}
    # Python:
    config = BuildAllConfig(
        eth_http_url="...",
        # ... other fields
    )

    # Go: clients, err := BuildAll(config, privateKey)
    # Python:
    try:
        clients = build_all(config, private_key)
    except Exception as e:
        # Handle error

    # Go: isRegistered, err := clients.ElReader.IsOperatorRegistered(address)
    # Python:
    try:
        is_registered = clients.el_reader.is_operator_registered(address)
    except Exception as e:
        # Handle error

**Contract Addresses**: The contract addresses are the same between Go and Python SDKs, so you can use your existing configuration.

Using eigensdk
--------------

To demonstrate using `eigensdk`, here's how you can find the list of operators registered on `EigenDA <https://docs.eigenlayer.xyz/eigenda/overview/>`_, a sample AVS:

.. code-block:: python

    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> 
    >>> # Note: You'll need to provide all required contract addresses
    >>> config = BuildAllConfig(
    ...     eth_http_url='https://ethereum-rpc.publicnode.com',
    ...     registry_coordinator_addr='0x0BAAc79acD45A023E19345c352d8a7a83C4e5656',
    ...     operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
    ...     rewards_coordinator_addr='0x7750d328b314EfFa365A0402CcfD489B80B0adda',
    ...     permission_controller_addr='0x00000000000000000000000000000000000000000',
    ...     service_manager_addr='0x870679E138bCdf293b7ff14dD44b70FC97e12fc0',
    ...     allocation_manager_addr='0x3A93c17D806bf74066d7e2c962b7a0F49b97e1Cf',
    ...     delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
    ...     avs_name="eigenda",
    ... )
    >>> 
    >>> # You'll need a private key for transaction operations
    >>> private_key = "your_private_key_here"  # For read-only operations, use any valid key
    >>> clients = build_all(config, private_key)
    >>> 
    >>> # Get operators in quorums 0 and 1
    >>> quorums = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
    ...     quorum_numbers=[0, 1]
    ... )
    >>> quorums
    [[
        OperatorStateRetrieverOperator(
            operator='0x4Cd2...Bd0a',
            operator_id='0x62fd...e8ee',
            stake=45675515801958122764368
        ), ...
    ], [
        OperatorStateRetrieverOperator(
            operator='0xDCeb...3040',
            operator_id='0x6507...e37a',
            stake=100000000000000000000
    ), ...]]

.. note::

   You can find a list of EigenDA contracts' addresses `here <https://github.com/Layr-Labs/eigenlayer-middleware/?tab=readme-ov-file#deployments>`_.

To calculate the total stake amount in both quorums 0 and 1:

.. code-block:: python

    >>> print(sum([operator.stake for operator in quorums[0]]) / 10**18)
    3677484.732396392
    >>> print(sum([operator.stake for operator in quorums[1]]) / 10**18)
    52989059.6562653