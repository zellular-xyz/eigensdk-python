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

Install `eigensdk-python` using ``pip``. It is recommended to perform this installation within a virtual environment (:ref:`virtualenv <setup_environment>`):

.. code-block:: shell

    $ pip3 install git+https://github.com/zellular-xyz/eigensdk-python

Using eigensdk
--------------

To demonstrate using `eigensdk`, here's how you can find the list of operators registered on `EigenDA <https://docs.eigenlayer.xyz/eigenda/overview/>`_, a sample AVS:

.. code-block:: python

    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> config = BuildAllConfig(
    ...     eth_http_url='https://ethereum-rpc.publicnode.com',
    ...     registry_coordinator_addr='0x0BAAc79acD45A023E19345c352d8a7a83C4e5656',
    ...     operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
    ... )
    >>> clients = build_all(config)
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