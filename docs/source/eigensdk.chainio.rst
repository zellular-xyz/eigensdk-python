.. _eigensdk.chainio:

eigensdk.chainio
================

eigensdk.chainio.clients.builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.builder.BuildAllConfig(eth_http_url: str, registry_coordinator_addr: Address, operator_state_retriever_addr: Address, rewards_coordinator_addr: Address, permission_controller_addr: Address, service_manager_addr: Address, allocation_manager_addr: Address, instant_slasher_addr: Address, delegation_manager_addr: Address, avs_name: str)

    This class creates a configuration object used to initialize and configure clients for interacting with the EigenLayer and integrated AVS blockchain infrastructure. It includes parameters to connect to the Ethereum network, AVS services.

    :param eth_http_url: URL for the Ethereum HTTP RPC endpoint.
    :param registry_coordinator_addr: The blockchain address of the registry coordinator contract.
    :param operator_state_retriever_addr: The blockchain address of the operator state retriever contract.
    :param rewards_coordinator_addr: The blockchain address of the rewards coordinator contract.
    :param permission_controller_addr: The blockchain address of the permission controller contract.
    :param service_manager_addr: The blockchain address of the service manager contract.
    :param allocation_manager_addr: The blockchain address of the allocation manager contract.
    :param instant_slasher_addr: The blockchain address of the instant slasher contract.
    :param delegation_manager_addr: The blockchain address of the delegation manager contract.
    :param avs_name: The name of the AVS for which the clients are being built.

.. py:function:: build_all(config: BuildAllConfig, config_ecdsa_private_key: str) -> Clients

    Instantiates and returns a collection of client objects that facilitate interaction with the EigenLayer core contracts and the AVS registry contracts. This method leverages the provided configuration to connect and authenticate interactions across the blockchain network.

    :param config: A `BuildAllConfig` object containing all necessary configuration details.
    :param config_ecdsa_private_key: A private key used for blockchain transactions and operations.
    :return: A `Clients` object containing all the initialized client instances.

Example Usage
-------------

Below is an example of how to use the `BuildAllConfig` and `build_all` functions to set up the necessary clients for interacting with the EigenLayer infrastructure. The example demonstrates setting up configuration, building clients, and printing out the instantiated client objects:

.. code-block:: python

    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> config = BuildAllConfig(
    ...     eth_http_url='https://ethereum-rpc.publicnode.com',
    ...     avs_name="eigenda",
    ...     registry_coordinator_addr='0x0BAAc79acD45A023E19345c352d8a7a83C4e5656',
    ...     operator_state_retriever_addr='0xD5D7fB4647cE79740E6e83819EFDf43fa74F8C31',
    ...     rewards_coordinator_addr='0x7750d328b314EfFa365A0402CcfD489B80B0adda',
    ...     permission_controller_addr='0x0000000000000000000000000000000000000000',
    ...     service_manager_addr='0x870679E138bCdf293b7ff14dD44b70FC97e12fc0',
    ...     allocation_manager_addr='0x3A93c17D806bf74066d7e2c962b7a0F49b97e1Cf',
    ...     instant_slasher_addr='0x0000000000000000000000000000000000000000',
    ...     delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
    ... )
    >>> clients = build_all(config, "your_private_key_here")
    >>> from pprint import pprint
    >>> pprint(clients.__dict__)
    {
        'avs_registry_reader': <eigensdk.chainio.clients.avsregistry.reader.AvsRegistryReader object at 0x715d7f72d0d0>,
        'avs_registry_writer': <eigensdk.chainio.clients.avsregistry.writer.AvsRegistryWriter object at 0x715d7f72d110>,
        'el_reader': <eigensdk.chainio.clients.elcontracts.reader.ELReader object at 0x715d7f89a450>,
        'el_writer': <eigensdk.chainio.clients.elcontracts.writer.ELWriter object at 0x715d7f89a490>,
        'eth_http_client': <web3.main.Web3 object at 0x715d83c009d0>,
        'wallet': <eth_account.signers.local.LocalAccount object at 0x715d83c123d0>
    }

clients.elcontracts.reader
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.elcontracts.reader.ELReader(allocation_manager: Contract, avs_directory: Contract, delegation_manager: Contract, permission_controller: Contract, reward_coordinator: Contract, strategy_manager: Contract, logger: logging.Logger, eth_http_client: Web3, strategy_abi: List[Dict[str, Any]], erc20_abi: List[Dict[str, Any]])

    The ``ELReader`` class is responsible for reading data from various smart contracts related to EigenLayer's core functionalities. It allows for interaction with smart contracts such as the allocation manager, AVS directory, delegation manager, permission controller, reward coordinator, and strategy manager.

    :param allocation_manager: A Web3 contract instance for the allocation manager contract.
    :param avs_directory: A Web3 contract instance for the AVS directory contract.
    :param delegation_manager: A Web3 contract instance for the delegation manager contract.
    :param permission_controller: A Web3 contract instance for the permission controller contract.
    :param reward_coordinator: A Web3 contract instance for the reward coordinator contract.
    :param strategy_manager: A Web3 contract instance for the strategy manager contract.
    :param logger: A logging.Logger instance for logging.
    :param eth_http_client: A Web3 instance connected to an Ethereum node.
    :param strategy_abi: ABI list for strategy contracts.
    :param erc20_abi: ABI list for ERC20 token contracts.

.. py:method:: is_operator_registered(operator_addr: Address) -> bool

    Checks if an operator is registered in the delegation manager.

    :param operator_addr: The blockchain address of the operator.
    :return: True if the operator is registered, otherwise False.

    .. code-block:: python

        >>> address = "0x4Cd2086E1d708E65Db5d4f5712a9CA46Ed4BBd0a"
        >>> clients.el_reader.is_operator_registered(address)
        True

.. py:method:: get_operator_details(operator: Dict[str, Any]) -> Dict[str, Any]

    Retrieves detailed information about a registered operator.

    :param operator: A dictionary containing operator information including the address.
    :return: A dictionary containing details about the operator.

.. py:method:: get_allocatable_magnitude(operator_addr: Address, strategy_addr: Address) -> int

    Retrieves the allocatable magnitude for an operator in a specific strategy.

    :param operator_addr: The blockchain address of the operator.
    :param strategy_addr: The blockchain address of the strategy.
    :return: The allocatable magnitude as an integer.

.. py:method:: get_allocation_info(operator_addr: Address, strategy_addr: Address) -> List[Dict[str, Any]]

    Fetches allocation information for an operator in a specific strategy.

    :param operator_addr: The blockchain address of the operator.
    :param strategy_addr: The blockchain address of the strategy.
    :return: A list of dictionaries containing allocation details.

.. py:method:: is_operator_registered_with_avs(operator_address: Address, avs_address: Address) -> bool

    Checks if an operator is registered with a specific AVS.

    :param operator_address: The blockchain address of the operator.
    :param avs_address: The blockchain address of the AVS.
    :return: True if the operator is registered with the AVS, otherwise False.

.. py:method:: get_operator_shares(operator_address: Address, strategy_addresses: List[Address]) -> List[int]

    Retrieves the shares an operator has across multiple strategies.

    :param operator_address: The blockchain address of the operator.
    :param strategy_addresses: A list of strategy addresses to query.
    :return: A list of share amounts corresponding to each strategy.

.. py:method:: get_strategy_and_underlying_token(strategy_addr: Address) -> Tuple[Contract, str]

    Fetches the smart contract instance of a strategy and its underlying token address.

    :param strategy_addr: The blockchain address of the strategy.
    :return: A tuple containing the strategy contract and the underlying token address.

    .. code-block:: python

        >>> strategy_addr = "0x93c4b944D05dfe6df7645A86cd2206016c51564D"
        >>> strategy_contract, token_address = clients.el_reader.get_strategy_and_underlying_token(strategy_addr)
        >>> strategy_contract
        <web3._utils.datatypes.Contract object at 0x7914d01be910>
        >>> token_address
        '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84'

    .. note::

       Available strategies are listed `here <https://github.com/Layr-Labs/eigenlayer-contracts/tree/dev?tab=readme-ov-file#strategies---eth>`_.


.. py:method:: get_strategy_and_underlying_erc20_token(strategy_addr: Address) -> Tuple[Contract, Contract, Address]

    Fetches the smart contract instance of a strategy, the contract instance of the underlying ERC20 token, and its address.

    :param strategy_addr: The blockchain address of the strategy.
    :return: A tuple containing the strategy contract, underlying ERC20 token contract, and the token address.

    .. code-block:: python

        >>> strategy_addr = "0x93c4b944D05dfe6df7645A86cd2206016c51564D"
        >>> strategy_contract, token_contract, token_address = clients.el_reader.get_strategy_and_underlying_erc20_token(strategy_addr)
        >>> strategy_contract
        <web3._utils.datatypes.Contract object at 0x7914d00ae7d0>
        >>> token_contract
        <web3._utils.datatypes.Contract object at 0x7914d007bd50>
        >>> token_address
        '0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84'

.. py:method:: calculate_delegation_approval_digest_hash(staker: Address, operator: Address, delegation_approver: Address, approver_salt: bytes, expiry: int) -> bytes

    Calculates the hash of a delegation approval digest.

    :param staker: The blockchain address of the staker.
    :param operator: The blockchain address of the operator.
    :param delegation_approver: The blockchain address of the delegation approver.
    :param approver_salt: Salt bytes for the hash calculation.
    :param expiry: Expiry time for the approval.
    :return: The calculated hash as bytes.

.. py:method:: calculate_operator_avs_registration_digest_hash(operator: Address, avs: Address, salt: bytes, expiry: int) -> bytes

    Calculates the hash of an operator AVS registration digest.

    :param operator: The blockchain address of the operator.
    :param avs: The blockchain address of the AVS.
    :param salt: Salt bytes for the hash calculation.
    :param expiry: Expiry time for the registration.
    :return: The calculated hash as bytes.

clients.elcontracts.writer
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.elcontracts.writer.ELWriter(slasher: Contract, delegation_manager: Contract, strategy_manager: Contract, strategy_manager_addr: Address, avs_directory: Contract, el_reader: ELReader, logger: logging.Logger, eth_http_client: Web3, pk_wallet: LocalAccount)

    The ``ELWriter`` class is designed for writing data to various smart contracts related to EigenLayer's core functionalities. It facilitates interaction with contracts such as the slasher, delegation manager, strategy manager, and AVS directory through transactional methods.

    :param slasher: A Web3 contract instance of the slasher contract.
    :param delegation_manager: A Web3 contract instance of the delegation manager contract.
    :param strategy_manager: A Web3 contract instance of the strategy manager contract.
    :param strategy_manager_addr: The blockchain address of the strategy manager contract.
    :param avs_directory: A Web3 contract instance of the AVS directory contract.
    :param el_reader: An instance of ELReader for reading contract data.
    :param logger: A logging.Logger instance for logging activities.
    :param eth_http_client: A Web3 instance connected to an Ethereum node.
    :param pk_wallet: A LocalAccount instance representing the private key wallet used for transactions.

.. py:method:: register_as_operator(operator: Operator) -> TxReceipt

    Registers a new operator in the delegation manager.

    :param operator: An ``Operator`` object containing the details to be registered.
    :return: A transaction receipt object indicating the result of the registration.

.. py:method:: update_operator_details(operator: Operator) -> TxReceipt

    Updates the details of an existing operator in the delegation manager.

    :param operator: An ``Operator`` object containing the updated details.
    :return: A transaction receipt object indicating the result of the update.

.. py:method:: deposit_erc20_into_strategy(strategy_addr: Address, amount: int) -> TxReceipt

    Deposits ERC20 tokens into a specified strategy contract.

    :param strategy_addr: The blockchain address of the strategy.
    :param amount: The amount of tokens to be deposited.
    :return: A transaction receipt object indicating the result of the deposit.

Example Usage
-------------

The following example demonstrates how to use the `ELWriter` class to register an operator, update operator details, and deposit tokens into a strategy:

.. code-block:: python

    >>> from eigensdk._types import Operator
    >>> operator = Operator(
    ...     address='0x123...',
    ...     earnings_receiver_address='0x456...',
    ...     delegation_approver_address='0x789...',
    ...     staker_opt_out_window_blocks=10,
    ...     metadata_url='http://example.com'
    ... )
    >>> receipt = clients.el_writer.register_as_operator(operator)
    >>> print(f"Operator registered with transaction hash: {receipt['transactionHash'].hex()}")

    >>> updated_operator = operator
    >>> updated_operator.staker_opt_out_window_blocks = 20
    >>> receipt = clients.el_writer.update_operator_details(updated_operator)
    >>> print(f"Operator details updated with transaction hash: {receipt['transactionHash'].hex()}")

    >>> receipt = clients.el_writer.deposit_erc20_into_strategy('0xabc...', 1000)
    >>> print(f"Deposited tokens with transaction hash: {receipt['transactionHash'].hex()}")

This example illustrates how to interact with the `ELWriter` methods for operator management and strategy interactions within the EigenLayer ecosystem.

clients.avsregistry.reader
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.avsregistry.reader.AvsRegistryReader(registry_coordinator_addr: Address, registry_coordinator: Contract, bls_apk_registry_addr: Address, bls_apk_registry: Contract, operator_state_retriever: Contract, stake_registry: Contract, logger: logging.Logger, eth_http_client: Web3)

    The ``AvsRegistryReader`` class is designed to read data from AVS-related contracts within the EigenLayer ecosystem, providing access to quorum, operator, and stake information.

    :param registry_coordinator_addr: The blockchain address of the registry coordinator contract.
    :param registry_coordinator: A Web3 contract instance of the registry coordinator.
    :param bls_apk_registry_addr: The blockchain address of the BLS APK registry contract.
    :param bls_apk_registry: A Web3 contract instance of the BLS APK registry.
    :param operator_state_retriever: A Web3 contract instance of the operator state retriever.
    :param stake_registry: A Web3 contract instance of the stake registry.
    :param logger: A logging.Logger instance for logging.
    :param eth_http_client: A Web3 instance connected to an Ethereum node.

.. py:method:: get_quorum_count() -> int

    Retrieves the number of quorums registered in the system.

    :return: The total count of quorums.

.. py:method:: get_operators_stake_in_quorums_at_current_block(quorum_numbers: List[int]) -> List[List[OperatorStateRetrieverOperator]]

    Fetches the stakes of operators in specified quorums at the current blockchain block.

    :param quorum_numbers: A list of quorum numbers to query.
    :return: A list of lists, each containing OperatorStateRetrieverOperator objects representing the stake details of operators within each quorum.

.. py:method:: get_operators_stake_in_quorums_at_block(quorum_numbers: List[int], block_number: int) -> List[List[OperatorStateRetrieverOperator]]

    Retrieves the stakes of operators in specified quorums at a given block number.

    :param quorum_numbers: A list of quorum numbers to query.
    :param block_number: The specific block number at which to retrieve the data.
    :return: A list of lists, with each inner list containing OperatorStateRetrieverOperator objects representing operators' stake details at the specified block.

.. py:method:: get_operator_addrs_in_quorums_at_current_block(quorum_numbers: List[int]) -> List[List[Address]]

    Fetches the addresses of operators in specified quorums at the current block.

    :param quorum_numbers: A list of quorum numbers to query.
    :return: A list of lists, where each inner list contains addresses of operators within a specific quorum.

.. py:method:: get_operator_id(operator_address: Address) -> bytes

    Retrieves the unique identifier of an operator based on their address.

    :param operator_address: The blockchain address of the operator.
    :return: The unique identifier of the operator as bytes.

.. py:method:: get_operator_from_id(operator_id: bytes) -> Address

    Retrieves the blockchain address of an operator based on their unique identifier.

    :param operator_id: The unique identifier of the operator.
    :return: The blockchain address of the operator.

.. py:method:: is_operator_registered(operator_address: Address) -> bool

    Checks whether an operator is registered within the AVS system.

    :param operator_address: The blockchain address of the operator.
    :return: True if the operator is registered, False otherwise.

.. py:method:: get_check_signatures_indices(reference_block_number: int, quorum_numbers: List[int], non_signer_operator_ids: List[int]) -> OperatorStateRetrieverCheckSignaturesIndices

    Retrieves indices for checking signatures based on the non-signing operators within specified quorums.

    :param reference_block_number: The block number to use as a reference for the check.
    :param quorum_numbers: A list of quorum numbers involved in the signature check.
    :param non_signer_operator_ids: A list of operator IDs that did not sign.
    :return: An object containing various indices related to the signature check.

clients.avsregistry.writer
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.avsregistry.writer.AvsRegistryWriter(service_manager_addr: Address, registry_coordinator: Contract, operator_state_retriever: Contract, stake_registry: Contract, bls_apk_registry: Contract, el_reader: ELReader, logger: logging.Logger, eth_http_client: Web3, pk_wallet: LocalAccount)

    The ``AvsRegistryWriter`` class facilitates interactions with AVS-related contracts to modify the state on the EigenLayer blockchain, such as registering and updating operator data.

    :param service_manager_addr: The blockchain address of the service manager contract.
    :param registry_coordinator: A Web3 contract instance of the registry coordinator.
    :param operator_state_retriever: A Web3 contract instance of the operator state retriever.
    :param stake_registry: A Web3 contract instance of the stake registry.
    :param bls_apk_registry: A Web3 contract instance of the BLS APK registry.
    :param el_reader: An instance of ELReader for reading contract data.
    :param logger: A logging.Logger instance for logging.
    :param eth_http_client: A Web3 instance connected to an Ethereum node.
    :param pk_wallet: A LocalAccount instance representing the private key wallet used for transactions.

.. py:method:: register_operator_in_quorum_with_avs_registry_coordinator(operator_ecdsa_private_key: str, operator_to_avs_registration_sig_salt: bytes, operator_to_avs_registration_sig_expiry: int, bls_key_pair: KeyPair, quorum_numbers: List[int], socket: str) -> TxReceipt

    Registers an operator within specified quorums in the AVS registry by providing BLS and ECDSA credentials.

    :param operator_ecdsa_private_key: The private key for the operator's ECDSA account.
    :param operator_to_avs_registration_sig_salt: A byte array used as salt in the registration signature.
    :param operator_to_avs_registration_sig_expiry: The expiry timestamp for the registration signature.
    :param bls_key_pair: A KeyPair object containing the operator's BLS public and private keys.
    :param quorum_numbers: A list of integers representing the quorums in which the operator should be registered.
    :param socket: A string representing the operator's network socket.
    :return: A transaction receipt indicating the result of the registration operation.

.. py:method:: update_stakes_of_entire_operator_set_for_quorums(operators_per_quorum: List[List[Address]], quorum_numbers: List[int]) -> TxReceipt

    Updates the stake assignments for an entire set of operators across specified quorums.

    :param operators_per_quorum: A list of lists containing the addresses of operators in each quorum.
    :param quorum_numbers: A list of integers representing the quorums to be updated.
    :return: A transaction receipt indicating the result of the stake update.

.. py:method:: update_stakes_of_operator_subset_for_all_quorums(operators: List[Address]) -> TxReceipt

    Updates the stakes for a subset of operators across all quorums.

    :param operators: A list of operator addresses to update.
    :return: A transaction receipt indicating the result of the stake updates.

.. py:method:: deregister_operator(quorum_numbers: List[int]) -> TxReceipt

    Deregisters an operator from specified quorums within the AVS system.

    :param quorum_numbers: A list of integers representing the quorums from which the operator should be deregistered.
    :return: A transaction receipt indicating the result of the deregistration.

.. py:method:: update_socket(socket: str) -> TxReceipt

    Updates the network socket information for the operator in the registry.

    :param socket: The new socket information as a string.
    :return: A transaction receipt indicating the result of the update.

Example Usage
-------------

The following examples demonstrate how to use the `AvsRegistryWriter` class to perform various operations like registering an operator, updating stakes, and managing operator details within the AVS system:

.. code-block:: python

    >>> from eigensdk.crypto.bls.attestation import KeyPair
    >>> from eth_account import Account
    >>> # Example key pairs and accounts should be securely managed
    >>> operator_ecdsa_private_key = "0x123abc..."
    >>> operator_account = Account.from_key(operator_ecdsa_private_key)
    >>> bls_key_pair = KeyPair.generate()  # Generate a BLS key pair
    >>> quorum_numbers = [0, 1]
    >>> socket_info = "192.168.1.1:30303"

    # Register an operator with AVS registry coordinator
    >>> receipt = clients.avs_writer.register_operator_in_quorum_with_avs_registry_coordinator(
    ...     operator_ecdsa_private_key,
    ...     b'some_salt',
    ...     1652937600,  # Expiry timestamp example
    ...     bls_key_pair,
    ...     quorum_numbers,
    ...     socket_info,
    ... )
    >>> print(f"Operator registered with transaction hash: {receipt.transactionHash.hex()}")

    # Example of updating stakes for a set of operators across specified quorums
    >>> operators_per_quorum = [['0xAbc...', '0xDef...'], ['0x123...', '0x456...']]
    >>> receipt = clients.avs_writer.update_stakes_of_entire_operator_set_for_quorums(
    ...     operators_per_quorum,
    ...     quorum_numbers,
    ... )
    >>> print(f"Stakes updated with transaction hash: {receipt.transactionHash.hex()}")

    # Deregister an operator from specific quorums
    >>> receipt = clients.avs_writer.deregister_operator(quorum_numbers)
    >>> print(f"Operator deregistered with transaction hash: {receipt.transactionHash.hex()}")

    # Update socket information for the registry
    >>> new_socket_info = "192.168.1.1:40404"
    >>> receipt = clients.avs_writer.update_socket(new_socket_info)
    >>> print(f"Socket updated with transaction hash: {receipt.transactionHash.hex()}")

This example section shows how to use the AvsRegistryWriter class to manage operator registrations and updates within the EigenLayer's AVS system. These operations include registering an operator with its BLS and ECDSA credentials, updating stake information across quorums, deregistering an operator, and updating network socket information.