.. _eigensdk.services:

eigensdk.services
=================

eigensdk.services.operatorsinfo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``OperatorsInfoServiceInMemory`` is a service designed to manage and maintain a local in-memory store of operator details such as public keys and network socket information. It periodically updates its data by querying the blockchain through an ``AvsRegistryReader`` instance.

Initialization
--------------

The service is initialized with the following parameters:

- **avs_registry_reader**: An instance of ``AvsRegistryReader`` used to access operator-related data on the blockchain.
- **start_block_pub**: The starting block number for querying registered public keys.
- **start_block_socket**: The starting block number for querying socket information.
- **check_interval**: The interval in seconds between checks for updates.
- **log_filter_query_block_range**: The range of blocks to query in one request.
- **logger**: An optional logger instance for logging events and errors.

.. py:class:: OperatorsInfoServiceInMemory(avs_registry_reader: AvsRegistryReader, start_block_pub: int = 0, start_block_socket: int = 0, check_interval: int = 10, log_filter_query_block_range: int = 10000, logger: Optional[logging.Logger] = None)

    Initializes a new instance of the ``OperatorsInfoServiceInMemory``.

    :param avs_registry_reader: Instance of ``AvsRegistryReader`` for blockchain queries.
    :param start_block_pub: Starting block number for public key queries.
    :param start_block_socket: Starting block number for socket info queries.
    :param check_interval: Time interval between update checks.
    :param log_filter_query_block_range: Block range for each query to the blockchain.
    :param logger: Logger for event logging.

Functionality
-------------

The service runs continuously in a separate thread, periodically updating its internal data stores based on the latest information from the blockchain. It supports the following functionalities:

- **Operator Public Key Retrieval**: Fetches and stores the latest public keys registered on the blockchain.
- **Operator Socket Information Retrieval**: Fetches and stores the latest socket information registered on the blockchain.
- **Operator Info Retrieval**: Provides a method to retrieve detailed information about an operator given their address.

.. py:method:: get_operator_info(operator_addr: Address) -> OperatorInfo

    Retrieves detailed information about an operator, including their socket information and public keys.

    :param operator_addr: The blockchain address of the operator.
    :return: An instance of ``OperatorInfo`` containing the operator's details.

Example Usage
-------------

The service can be used in an application that requires up-to-date information about blockchain operators, such as in a decentralized application (dApp) that interacts with various blockchain services:

.. code-block:: python

    >>> operator_info_service = OperatorsInfoServiceInMemory(clients.avs_registry_reader)
    >>> operator_info = operator_info_service.get_operator_info('0x123...')
    >>> print(f"Operator Socket: {operator_info.socket}, Public Keys: {operator_info.pub_keys}")


This example initializes the service and retrieves operator information, demonstrating how to integrate and utilize the ``OperatorsInfoServiceInMemory`` within larger systems.

eigensdk.services.avsregistry
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``AvsRegistryService`` is designed to aggregate and provide access to detailed state information about operators and their stakes across different quorums. It utilizes data from both the ``AvsRegistryReader`` and ``OperatorsInfoServiceInMemory`` to construct comprehensive views of the AVS (Autonomous Validation Services) landscape at specific blockchain states.

Initialization
--------------

The service is initialized with instances of ``AvsRegistryReader`` and ``OperatorsInfoServiceInMemory``, along with a logger for event logging.

.. py:class:: AvsRegistryService(avs_registry_reader: AvsRegistryReader, operator_info_service: OperatorsInfoServiceInMemory, logger: logging.Logger)

    Initializes a new instance of the ``AvsRegistryService``.

    :param avs_registry_reader: Instance of ``AvsRegistryReader`` for reading blockchain data.
    :param operator_info_service: Instance of ``OperatorsInfoServiceInMemory`` for managing in-memory operator data.
    :param logger: Logger for event logging.

Functionality
-------------

The service offers functionalities to retrieve aggregated operator states and quorum states at specific blocks, helping in the analysis and management of AVS.

.. py:method:: get_operators_avs_state_at_block(quorum_numbers: List[int], block_number: int) -> Dict[bytes, OperatorAvsState]

    Retrieves the AVS state of operators at a specific blockchain block.

    :param quorum_numbers: List of quorum numbers to query.
    :param block_number: The blockchain block number at which to get the state.
    :return: A dictionary mapping operator IDs to their ``OperatorAvsState``.

.. py:method:: get_quorums_avs_state_at_block(quorum_numbers: List[int], block_number: int) -> Dict[int, Dict[str, Union[int, G1Point]]]

    Aggregates the state of specified quorums at a given block number, including the aggregated public keys and total stakes.

    :param quorum_numbers: List of quorum numbers to aggregate.
    :param block_number: The blockchain block number at which to aggregate the state.
    :return: A dictionary with quorum numbers as keys and details including aggregated public keys, total stakes, and block numbers.

Example Usage
-------------

The following example demonstrates how to use the ``AvsRegistryService`` to fetch and display operator and quorum states at a specific blockchain block:

.. code-block:: python

    >>> avs_registry_service = AvsRegistryService(clients.avs_registry_reader, operator_info_service, logger)
    >>> quorum_numbers = [0, 1]
    >>> block_number = 12345
    >>> operators_state = avs_registry_service.get_operators_avs_state_at_block(quorum_numbers, block_number)
    >>> print(operators_state)
    >>> quorums_state = avs_registry_service.get_quorums_avs_state_at_block(quorum_numbers, block_number)
    >>> print(quorums_state)

This example shows how to initialize the service and retrieve detailed state information for operators and quorums, providing insights into the current and historical configurations of the AVS within the blockchain.


eigensdk.services.bls_aggregation.blsagg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``BlsAggregationService`` is integral to aggregating Boneh-Lynn-Shacham (BLS) signatures in distributed validation systems, ensuring task authenticity and integrity across multiple nodes.

Initialization
--------------

The service is initiated with an instance of ``AvsRegistryService`` and a cryptographic hash function. These components enable it to verify and aggregate signatures while interacting with blockchain state data.

.. py:class:: BlsAggregationService(avs_registry_service: AvsRegistryService, hash_function: any)

    Initializes a new instance of ``BlsAggregationService``.

    :param avs_registry_service: An instance of ``AvsRegistryService`` used for querying blockchain data.
    :param hash_function: A cryptographic hash function used for digest generation.

Functionality
-------------

The service provides methods to initialize new tasks, process new signatures, and retrieve aggregated responses. It verifies signatures against blockchain data and aggregates them if they meet predefined quorum requirements.

.. py:method:: initialize_new_task(task_index: int, task_created_block: int, quorum_numbers: List[int], quorum_threshold_percentages: List[int], time_to_expiry: int)

    Prepares a new task for aggregation, setting initial parameters and storing them internally.

.. py:method:: process_new_signature(task_index: int, task_response: str, bls_signature: Signature, operator_id: int)

    Processes and aggregates a new BLS signature related to a specific task, verifying its authenticity and adding it to the aggregate.

.. py:method:: get_aggregated_responses() -> Iterator[BlsAggregationServiceResponse]

    Yields completed task responses once they meet aggregation criteria, indicating successful validation.

Data Structures
---------------

- **TaskListItem**: Maintains task-specific data, including state of operator signatures and stake thresholds.
- **AggregatedOperators**: Stores aggregated public keys and signatures for operators who have signed a specific task response.

Example Usage
-------------

The following example demonstrates initializing the service, managing task signatures, and validating task completion:

.. code-block:: python

    >>> bls_aggregation_service = BlsAggregationService(avs_registry_service, hash_function)
    >>> task_index = 1
    >>> quorum_numbers = [0, 1]
    >>> quorum_thresholds = [70, 70]
    >>> # Initialize a new task
    >>> bls_aggregation_service.initialize_new_task(task_index, 123456, quorum_numbers, quorum_thresholds, 3600)
    >>> # Process a new signature
    >>> operator_id = 101
    >>> task_response = 'response data'
    >>> bls_signature = Signature(...)  # Assuming a valid BLS signature
    >>> bls_aggregation_service.process_new_signature(task_index, task_response, bls_signature, operator_id)
    >>> # Retrieve and handle aggregated responses
    >>> for response in bls_aggregation_service.get_aggregated_responses():
    ...     print(response)

This service is crucial for ensuring tasks are validated correctly and efficiently, using cryptographic guarantees provided by BLS signatures and blockchain data.

