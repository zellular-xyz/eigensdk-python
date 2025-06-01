.. _quickstart:

Quickstart
==========

Dependencies
------------

The installation requires the [MCL](https://github.com/herumi/mcl) native package. To install MCL, execute the following commands:

.. code-block:: shell

    $ sudo apt install libgmp3-dev
    $ wget https://github.com/herumi/mcl/archive/refs/tags/v1.93.zip
    $ unzip v1.93.zip
    $ cd mcl-1.93
    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    $ sudo make install

Installation
------------

.. _setup_environment:

**Option 1: Manual Installation**

Install `eigensdk-python` using ``pip``. It is recommended to perform this installation within a virtual environment:

.. code-block:: shell

    $ python -m venv eigensdk-env
    $ source eigensdk-env/bin/activate  # On Windows: eigensdk-env\Scripts\activate
    $ pip install git+https://github.com/abramsymons/eigensdk-python

**Option 2: Docker Setup (Recommended)**

A complete Docker-based environment is provided, featuring Python 3.12, pre-installed MCL library, Foundry, EigenLayer contracts, and development tools:

.. code-block:: shell

    $ git clone https://github.com/abramsymons/eigensdk-python
    $ cd eigensdk-python
    $ make build
    $ make test

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
    ...     instant_slasher_addr='0x0000000000000000000000000000000000000000',
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