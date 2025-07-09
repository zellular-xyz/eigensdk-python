EigenSDK Python Documentation
#############################

**eigensdk-python** is a SDK for EigenLayer, derived from the official `eigensdk-go <https://github.com/layr-Labs/eigensdk-go/tree/master/>`_ implementation.

It enables BLS `signing <https://eth2book.info/capella/part2/building_blocks/signatures/>`_ and `aggregation <https://eth2book.info/capella/part2/building_blocks/signatures/#aggregation>`_, while also providing a wrapper for interacting with both EigenLayer's `core contracts <https://github.com/Layr-Labs/eigenlayer-contracts>`_ and `AVS-specific contracts <https://github.com/Layr-Labs/eigenlayer-middleware/>`_.

Getting Started
~~~~~~~~~~~~~~~

.. warning::

   This library is currently in active development. While it can be used for testing and development purposes, please exercise caution when using in production environments.

- Ready to code? → :ref:`quickstart`
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
    :caption: API

    eigensdk.chainio
    eigensdk.crypto
    eigensdk.types
