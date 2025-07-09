.. _quickstart:

Quickstart
==========

Requirements
------------

- Python 3.12+
- Ubuntu 24.04+ / macOS 13+ / Windows 11+
- Git for installation from source

Dependencies
------------

The `MCL <https://github.com/herumi/mcl>`_ native library is required for BLS signing & verification.

System dependencies
^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    sudo apt update
    sudo apt install libgmp3-dev cmake make wget unzip

Install MCL library
^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
    unzip v1.93.zip
    cd mcl-1.93
    mkdir build && cd build
    cmake .. && make
    sudo make install

Installation
------------

Installing from PyPI
^^^^^^^^^^^^^^^^^^^^

After installing the MCL library, you can install or upgrade `eigensdk-python` via:

.. code-block:: shell

    pip install eigensdk --upgrade

Installing from Source
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: shell

    git clone https://github.com/zellular-xyz/eigensdk-python
    cd eigensdk-python
    pip install .


Using EigenSDK
--------------

To demonstrate using `eigensdk`, here's how you can find the list of operators registered on `EigenDA <https://docs.eigenlayer.xyz/eigenda/overview/>`_, a sample AVS:

.. code-block:: python

    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> 
    >>> # Note: You'll need to provide all required contract addresses
    >>> config = BuildAllConfig(
    ...     eth_http_url='https://ethereum-rpc.publicnode.com',
    ...     avs_name="EigenDA",
    ...     registry_coordinator_addr='0x0BAAc79acD45A023E19345c352d8a7a83C4e5656',
    ...     operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
    ...     rewards_coordinator_addr='0x7750d328b314EfFa365A0402CcfD489B80B0adda',
    ...     permission_controller_addr='0x0000000000000000000000000000000000000000',
    ...     service_manager_addr='0x870679E138bCdf293b7ff14dD44b70FC97e12fc0',
    ...     allocation_manager_addr='0x3A93c17D806bf74066d7e2c962b7a0F49b97e1Cf',
    ...     delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
    ... )
    >>> 
    >>> # You'll need a private key for transaction operations
    >>> private_key = "your_private_key_here"  # For read-only operations, use any valid key
    >>> clients = build_all(config, private_key)
    >>> 
    >>> # Get operators in quorums 0,1
    >>> quorums = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
    ...     quorum_numbers=[0,1]
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
    ...
    >>> print(sum([operator.stake for operator in quorums[1]]) / 10**18)
    ...
