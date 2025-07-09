.. _eigensdk.chainio:

eigensdk.chainio
================

ELReader
~~~~~~~~~~~~~~~~~~~

The ELReader class provides read-only access to EigenLayer contracts, offering comprehensive functionality for querying operator information, allocation management, delegation status, rewards, and permissions.

.. autoclass:: eigensdk.chainio.clients.elcontracts.reader.ELReader
    :members:
    :undoc-members:
    :show-inheritance:

ELWriter
~~~~~~~~~~~~~~~~~~~

The ELWriter class provides write operations for EigenLayer contracts, enabling operator registration, strategy management, rewards processing, allocation modifications, and permission management.

.. autoclass:: eigensdk.chainio.clients.elcontracts.writer.ELWriter
    :members:
    :undoc-members:
    :show-inheritance:

AvsRegistryReader
~~~~~~~~~~~~~~~~~

The AvsRegistryReader class provides comprehensive read-only access to AVS (Autonomous Validation Service) registry contracts, offering functionality for quorum management, operator information retrieval, stake tracking, and public key management.

.. autoclass:: eigensdk.chainio.clients.avsregistry.reader.AvsRegistryReader
    :members:
    :undoc-members:
    :show-inheritance:

AVS Registry Writer
~~~~~~~~~~~~~~~~~~~

The AvsRegistryWriter class provides write operations for AVS registry contracts, enabling comprehensive management of operators, quorums, strategies, and rewards within the AVS ecosystem.

.. autoclass:: eigensdk.chainio.clients.avsregistry.writer.AvsRegistryWriter
    :members:
    :undoc-members:
    :show-inheritance:
