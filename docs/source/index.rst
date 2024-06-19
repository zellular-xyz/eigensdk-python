EigenSDK Python Documentation
#############################

**eigensdk-python** is a SDK for EigenLayer, derived from the official `eigensdk-go <https://github.com/layr-Labs/eigensdk-go/tree/master/>`_ implementation.

It enables BLS `signing <https://eth2book.info/capella/part2/building_blocks/signatures/>`_ and `aggregation <https://eth2book.info/capella/part2/building_blocks/signatures/#aggregation>`_, while also providing a wrapper for interacting with both EigenLayer's `core contracts <https://github.com/Layr-Labs/eigenlayer-contracts>`_ and `AVS-specific contracts <https://github.com/Layr-Labs/eigenlayer-middleware/>`_. Additionally, the SDK includes implementations of `NodeAPI <https://docs.eigenlayer.xyz/category/avs-node-api>`_ and `Metrics API <https://docs.eigenlayer.xyz/category/metrics>`_, offering essential tools for effective monitoring and management of AVS operations, ensuring a cohesive development environment within the EigenLayer ecosystem.

.. warning::

   This library is a PoC implemented for the EigenLayer hackathon. Do not use it in Production, testnet only.

Table of Contents
-----------------

.. toctree::
    :maxdepth: 1
    :caption: Intro

    quickstart

.. toctree::
    :maxdepth: 1
    :caption: API

    chainio
    crypto
    services
    nodeapi
    metrics
