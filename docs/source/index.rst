EigenSDK Python Documentation
#############################

**EigenSDK-Python** is a Python SDK for EigenLayer, derived from the official `EigenSDK-Go <https://github.com/layr-Labs/eigensdk-go/tree/master/>`_ implementation.

The SDK consists of two main modules:
- **Crypto Module**: Leverages the MCL (Multi-party Computation Library) to handle BLS signatures and aggregation operations, providing secure cryptographic functionality for the EigenLayer ecosystem.
- **ChainIO Module**: A comprehensive tool for interacting with both EigenLayer core contracts and middleware contracts, enabling read and write operations for all necessary functionality within the EigenLayer network.

This SDK provides essential tools for building and managing **AVS (Actively Validated Services)** within the EigenLayer ecosystem.

**Maintainership**: This SDK was originally developed by **Abram Symons** and is now actively maintained and extended by `iF3 Labs <https://github.com/if3-xyz>`_ under his supervision. The project originated as part of `Zellular <https://github.com/zellular-xyz>`_.

📬 **Contact**: `mail@if3.xyz <mailto:mail@if3.xyz>`_
📬 **Contact**: `abramsymons@gmail.com <mailto:abramsymons@gmail.com>`_
📬 **Contact**: `mail@zellular.xyz <mailto:mail@zellular.xyz>`_

Architecture Overview
~~~~~~~~~~~~~~~~~~~~

EigenSDK-Python is built around two core modules that work together to provide comprehensive EigenLayer functionality:

**Crypto Module** → **ChainIO Module** → **Your AVS**

- **Crypto Module**: Handles all cryptographic operations including BLS key generation, message signing, and signature aggregation using the MCL library
- **ChainIO Module**: Manages blockchain interactions with both EigenLayer core contracts and AVS-specific middleware contracts
- **Integration**: The modules work together - crypto operations generate the signatures and keys needed for on-chain registration and operations

**Typical Workflow:**

1. **Key Generation**: Use crypto module to generate BLS key pairs for operators
2. **Registration**: Use ChainIO module to register operators with EigenLayer core contracts
3. **AVS Registration**: Register operators with specific AVS using middleware contracts
4. **Operations**: Continuous signing, stake updates, and quorum management
5. **Aggregation**: Aggregate signatures from multiple operators for efficient verification

**Contract Interaction Hierarchy:**

- **Core Contracts**: Fundamental EigenLayer functionality (delegation, rewards, strategies)
- **Middleware Contracts**: AVS-specific logic (registry coordination, stake management)
- **Your AVS Contracts**: Custom business logic built on top of the EigenLayer infrastructure

Getting Started
~~~~~~~~~~~~~~~

.. warning::

   This library is not just for testnet and is updated based on the latest release of eigensdk-go. While it can be used for testing and development purposes, please exercise caution when using in production environments.

- Ready to code? → :ref:`QuickStart`
- Example AVS using this SDK? → `Incredible Squaring AVS <https://github.com/zellular-xyz/incredible-squaring-avs-python>`_
- Read the source? → `Github <https://github.com/zellular-xyz/eigensdk-python>`_

Table of Contents
~~~~~~~~~~~~~~~~~

.. toctree::
    :maxdepth: 1
    :caption: Intro

    quickstart

.. toctree::
    :maxdepth: 1
    :caption: Guides

    security
    advanced-examples
    performance
    troubleshooting

.. toctree::
    :maxdepth: 1
    :caption: API

    eigensdk.chainio
    eigensdk.crypto
    eigensdk.types
