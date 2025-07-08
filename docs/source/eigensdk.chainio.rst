.. _eigensdk.chainio:

eigensdk.chainio
================

AvsRegistryReader
~~~~~~~~~~~~~~~~~
.. autoclass:: eigensdk.chainio.clients.avsregistry.reader.AvsRegistryReader
    :members:
    :undoc-members:
    :show-inheritance:


eigensdk.chainio.clients.builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.chainio.clients.builder.BuildAllConfig(eth_http_url: str, registry_coordinator_addr: Address, operator_state_retriever_addr: Address, rewards_coordinator_addr: Address, permission_controller_addr: Address, service_manager_addr: Address, allocation_manager_addr: Address, delegation_manager_addr: Address, avs_name: str)

    This class creates a configuration object used to initialize and configure clients for interacting with the EigenLayer and integrated AVS blockchain infrastructure. It includes parameters to connect to the Ethereum network, AVS services.

    :param eth_http_url: URL for the Ethereum HTTP RPC endpoint.
    :param registry_coordinator_addr: The blockchain address of the registry coordinator contract.
    :param operator_state_retriever_addr: The blockchain address of the operator state retriever contract.
    :param rewards_coordinator_addr: The blockchain address of the rewards coordinator contract.
    :param permission_controller_addr: The blockchain address of the permission controller contract.
    :param service_manager_addr: The blockchain address of the service manager contract.
    :param allocation_manager_addr: The blockchain address of the allocation manager contract.
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
    ...     delegation_manager_addr='0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A',
    ... )
    >>> clients = build_all(config, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
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


eigensdk.chainio.clients.elcontracts.reader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ELReader class provides read-only access to EigenLayer contracts, offering comprehensive functionality for querying operator information, allocation management, delegation status, rewards, and permissions.

**Allocation Management Functions:**

- ``get_allocatable_magnitude(operator_addr, strategy_addr)`` - Returns the allocatable magnitude for a specific operator and strategy combination
- ``get_max_magnitudes(operator_addr, strategy_addrs)`` - Gets maximum magnitudes for an operator across multiple strategies
- ``get_allocation_info(operator_addr, strategy_addr)`` - Retrieves detailed allocation information including operator set IDs, AVS addresses, current magnitudes, pending differences, and effective blocks
- ``get_operator_sets_for_operator(operator_addr)`` - Returns all operator sets that a specific operator is registered with
- ``get_allocation_delay(operator_addr)`` - Gets the allocation delay configured for an operator
- ``get_registered_sets(operator_addr)`` - Returns all registered sets for an operator
- ``get_allocated_stake(operator_set, operator_addresses, strategy_addresses)`` - Gets allocated stake amounts for operators and strategies within an operator set
- ``get_operators_for_operator_set(operator_set)`` - Returns all operators that are members of a specific operator set
- ``get_num_operators_for_operator_set(operator_set)`` - Gets the count of operators in an operator set
- ``get_strategies_for_operator_set(operator_set)`` - Returns all strategies configured for an operator set
- ``get_encumbered_magnitude(operator_address, strategy_address)`` - Gets the encumbered magnitude for an operator/strategy pair

**Registration and Status Functions:**

- ``is_operator_registered_with_avs(operator_address, avs_address)`` - Checks if an operator is registered with a specific AVS
- ``is_operator_registered_with_operator_set(operator_addr, operator_set)`` - Verifies operator registration with an operator set
- ``is_operator_slashable(operator_address, operator_set)`` - Determines if an operator is slashable within an operator set
- ``is_operator_registered(operator_address)`` - Checks if an address is registered as an operator

**Delegation Functions:**

- ``get_operator_shares(operator_address, strategy_addresses)`` - Gets operator shares across multiple strategies
- ``get_staker_shares(staker_address)`` - Returns strategy addresses and corresponding share amounts for a staker
- ``get_delegated_operator(staker_address, block_number)`` - Gets the operator that a staker has delegated to, optionally at a specific block
- ``get_operator_details(operator)`` - Returns detailed operator information including delegation approver and allocation delay
- ``get_operator_shares_in_strategy(operator_addr, strategy_addr)`` - Gets operator shares in a specific strategy
- ``get_operators_shares(operator_addresses, strategy_addresses)`` - Gets shares for multiple operators across multiple strategies

**Delegation Approval Functions:**

- ``calculate_delegation_approval_digest_hash(staker, operator, delegation_approver, approver_salt, expiry)`` - Calculates the digest hash for delegation approval
- ``get_delegation_approver_salt_is_spent(delegation_approver, approver_salt)`` - Checks if a delegation approver salt has been used

**Withdrawal Functions:**

- ``get_pending_withdrawal_status(withdrawal_root)`` - Gets the status of a pending withdrawal using its root hash
- ``get_cumulative_withdrawals_queued(staker)`` - Returns the cumulative number of withdrawals queued for a staker

**Permission Management Functions:**

- ``can_call(account_address, appointee_address, target, selector)`` - Checks if an appointee can call a specific function on behalf of an account
- ``list_appointees(account_address, target, selector)`` - Lists all appointees for a specific account/target/selector combination
- ``list_appointee_permissions(account_address, appointee_address)`` - Returns all permissions granted to an appointee
- ``list_pending_admins(account_address)`` - Lists all pending admin addresses for an account
- ``list_admins(account_address)`` - Lists all current admin addresses for an account
- ``is_pending_admin(account_address, pending_admin_address)`` - Checks if an address is a pending admin
- ``is_admin(account_address, admin_address)`` - Verifies if an address is an admin

**Rewards System Functions:**

- ``get_distribution_roots_length()`` - Returns the total number of distribution roots in the rewards system
- ``curr_rewards_calculation_end_timestamp()`` - Gets the current rewards calculation end timestamp
- ``get_current_claimable_distribution_root()`` - Returns the current claimable distribution root with start/end blocks and total claimable amount
- ``get_root_index_from_hash(root_hash)`` - Gets the index of a distribution root from its hash
- ``get_cumulative_claimed(earner, token)`` - Returns cumulative rewards claimed by an earner for a specific token
- ``check_claim(claim)`` - Validates a rewards claim structure and returns whether it's valid
- ``get_operator_avs_split(operator, avs)`` - Gets the split percentage between operator and AVS for rewards
- ``get_operator_pi_split(operator)`` - Gets the operator's protocol incentive split percentage
- ``get_operator_set_split(operator, operator_set)`` - Gets the split percentage for an operator within an operator set
- ``get_curr_rewards_calculation_end_timestamp()`` - Returns the current rewards calculation end timestamp
- ``get_rewards_updater()`` - Gets the address authorized to update rewards
- ``get_default_operator_split_bips()`` - Returns the default operator split in basis points
- ``get_claimer_for(earner)`` - Gets the designated claimer address for an earner
- ``get_submission_nonce(avs)`` - Returns the submission nonce for an AVS

**Rewards Validation Functions:**

- ``get_is_avs_rewards_submission_hash(avs, hash)`` - Validates if a hash is a valid AVS rewards submission
- ``get_is_rewards_submission_for_all_hash(avs, hash)`` - Validates rewards submission for all hash
- ``get_is_rewards_for_all_submitter(submitter)`` - Checks if an address can submit rewards for all
- ``get_is_rewards_submission_for_all_earners_hash(avs, hash)`` - Validates submission for all earners hash
- ``get_is_operator_directed_avs_rewards_submission_hash(avs, hash)`` - Validates operator-directed AVS rewards submission
- ``get_is_operator_directed_operator_set_rewards_submission_hash(avs, hash)`` - Validates operator-directed operator set rewards submission

**Strategy and Token Functions:**

- ``get_strategy_and_underlying_token(strategy_addr)`` - Returns strategy contract instance and underlying token address
- ``get_strategy_and_underlying_erc20_token(strategy_addr)`` - Returns strategy contract, ERC20 token contract, and token address

**Registration Digest Functions:**

- ``calculate_operator_avs_registration_digest_hash(operator, avs, salt, expiry)`` - Calculates the digest hash for operator AVS registration

**Configuration Constants:**

- ``get_calculation_interval_seconds()`` - Returns the rewards calculation interval in seconds
- ``get_max_rewards_duration()`` - Gets the maximum allowed rewards duration
- ``get_max_retroactive_length()`` - Returns the maximum retroactive length for rewards
- ``get_max_future_length()`` - Gets the maximum future length for rewards
- ``get_genesis_rewards_timestamp()`` - Returns the genesis timestamp for the rewards system
- ``get_activation_delay()`` - Gets the activation delay for rewards
- ``get_deallocation_delay()`` - Returns the deallocation delay period
- ``get_allocation_configuration_delay()`` - Gets the allocation configuration delay
- ``get_num_operator_sets_for_operator(operator_address)`` - Returns the number of operator sets an operator is part of

**Slashing Functions:**

- ``get_slashable_shares(operator_address, operator_set, strategies)`` - Gets slashable shares for an operator in specific strategies
- ``get_slashable_shares_for_operator_sets_before(operator_sets, future_block)`` - Gets slashable shares for operator sets before a specific block
- ``get_slashable_shares_for_operator_sets(operator_sets)`` - Gets current slashable shares for operator sets

eigensdk.chainio.clients.elcontracts.writer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ELWriter class provides write operations for EigenLayer contracts, enabling operator registration, strategy management, rewards processing, allocation modifications, and permission management.

**Operator Registration and Management:**

- ``register_as_operator(operator)`` - Registers an address as an operator with delegation approver, allocation delay, and metadata URL
- ``update_operator_details(operator)`` - Updates existing operator details including delegation approver address
- ``update_metadata_uri(operator_address, uri)`` - Updates the metadata URI for an operator

**Strategy Operations:**

- ``deposit_erc20_into_strategy(strategy_addr, amount)`` - Deposits ERC20 tokens into a specified strategy, handling token approval and strategy deposit

**Rewards Management:**

- ``set_claimer_for(claimer)`` - Sets the designated claimer address for rewards
- ``process_claim(claim, recipient_address)`` - Processes a rewards claim and sends rewards to the specified recipient
- ``set_operator_avs_split(operator, avs, split)`` - Sets the split percentage between operator and AVS for rewards
- ``set_operator_pi_split(operator, split)`` - Sets the operator's protocol incentive split percentage

**Allocation Management:**

- ``modify_allocations(operator_address, avs_service_manager, operator_set_id, strategies, new_magnitudes)`` - Modifies operator allocations for specific strategies within an operator set
- ``clear_deallocation_queue(operator_address, strategies, nums_to_clear)`` - Clears pending deallocations from the deallocation queue
- ``set_allocation_delay(operator_address, delay)`` - Sets the allocation delay period for an operator

**Operator Set Management:**

- ``deregister_from_operator_sets(operator, request)`` - Deregisters an operator from specified operator sets
- ``register_for_operator_sets(registry_coordinator_addr, request)`` - Registers an operator for operator sets with BLS key registration and socket information

**Permission Management:**

- ``remove_permission(request)`` - Removes appointee permissions for specific function calls
- ``set_permission(request)`` - Grants appointee permissions for specific function calls
- ``accept_admin(request)`` - Accepts an admin role for an account
- ``add_pending_admin(request)`` - Adds a pending admin to an account
- ``remove_admin(request)`` - Removes an admin from an account
- ``remove_pending_admin(request)`` - Removes a pending admin from an account

**Utility Functions:**

- ``get_operator_id(operator_address)`` - Retrieves the operator ID for a given operator address
- ``set_avs_registrar(avs_address, registrar_address)`` - Sets the registrar address for an AVS

eigensdk.chainio.clients.avsregistry.reader
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The AvsRegistryReader class provides comprehensive read-only access to AVS (Autonomous Validation Service) registry contracts, offering functionality for quorum management, operator information retrieval, stake tracking, and public key management.

**Quorum and Operator Management:**

- ``get_quorum_count()`` - Returns the total number of quorums configured in the registry
- ``get_operator_status(operator_address)`` - Gets the current registration status of an operator (0=not registered, 1=registered)
- ``is_operator_registered(operator_address)`` - Boolean check for operator registration status
- ``query_registration_detail(operator_address)`` - Returns detailed registration information showing which quorums an operator is registered for
- ``is_operator_set_quorum(quorum_number)`` - Checks if a specific quorum is configured as an operator set

**Stake Retrieval Functions:**

- ``get_operators_stake_in_quorums_at_current_block(quorum_numbers)`` - Gets operator stakes for specified quorums at the current block
- ``get_operators_stake_in_quorums_at_block(quorum_numbers, block_number)`` - Gets operator stakes for specified quorums at a specific historical block
- ``get_operators_stake_in_quorums_of_operator_at_block(operator_ids, block_number)`` - Gets stake information for specific operators at a given block
- ``get_operators_stake_in_quorums_of_operator_at_current_block(operator_ids)`` - Gets stake information for specific operators at the current block
- ``get_operator_addrs_in_quorums_at_current_block(quorum_numbers)`` - Returns lists of operator addresses for each specified quorum

**Weight and Strategy Management:**

- ``weight_of_operator_for_quorum(quorum_number, operator_addr)`` - Gets the voting weight of an operator in a specific quorum
- ``strategy_params_length(quorum_number)`` - Returns the number of strategy parameters configured for a quorum
- ``strategy_params_by_index(quorum_number, index)`` - Gets strategy parameters (strategy address and multiplier) at a specific index
- ``get_strategy_params_at_index(quorum_number, index)`` - Alternative method to retrieve strategy parameters
- ``get_strategy_per_quorum_at_index(quorum_number, index)`` - Gets the strategy address for a quorum at a specific index
- ``get_restakeable_strategies()`` - Returns the list of all restakeable strategies supported by the AVS
- ``get_operator_restaked_strategies(operator)`` - Gets the list of strategies that a specific operator has restaked

**Stake History and Updates:**

- ``get_stake_history_length(operator_id, quorum_number)`` - Returns the length of stake history for an operator in a quorum
- ``get_stake_history(operator_id, quorum_number)`` - Gets the complete stake history for an operator in a quorum
- ``get_latest_stake_update(operator_id, quorum_number)`` - Gets the most recent stake update for an operator
- ``get_stake_update_at_index(operator_id, quorum_number, index)`` - Gets a specific stake update by index
- ``get_stake_at_block_number(operator_id, quorum_number, block_number)`` - Gets the stake amount at a specific block number
- ``get_stake_update_index_at_block_number(operator_id, quorum_number, block_number)`` - Gets the stake update index at a specific block

**Total Stake Information:**

- ``get_total_stake_history_length(quorum_number)`` - Returns the length of total stake history for a quorum
- ``get_current_total_stake(quorum_number)`` - Gets the current total stake for a quorum
- ``get_total_stake_update_at_index(quorum_number, index)`` - Gets total stake update information at a specific index
- ``get_total_stake_at_block_number_from_index(quorum_number, block_number, index)`` - Gets total stake at a block number from a specific index
- ``get_total_stake_indices_at_block_number(quorum_numbers, block_number)`` - Gets total stake indices for quorums at a specific block

**Configuration and Parameters:**

- ``get_minimum_stake_for_quorum(quorum_number)`` - Gets the minimum stake required to participate in a quorum
- ``get_stake_type_per_quorum(quorum_number)`` - Gets the stake type configuration for a quorum
- ``get_slashable_stake_look_ahead_per_quorum(quorum_number)`` - Gets the slashable stake lookahead period for a quorum

**Operator Identity and Mapping:**

- ``get_operator_id(operator_address)`` - Gets the unique operator ID (bytes32) for an operator address
- ``get_operator_from_id(operator_id)`` - Gets the operator address from an operator ID
- ``get_operator_id_from_operator_address(operator_address)`` - Alternative method to get operator ID from address
- ``get_operator_address_from_operator_id(operator_pubkey_hash)`` - Gets operator address from public key hash

**Public Key Management:**

- ``get_pubkey_from_operator_address(operator_address)`` - Gets the G1 public key for an operator
- ``get_apk_update(quorum_number, index)`` - Gets APK (Aggregated Public Key) update information including hash and block numbers
- ``get_current_apk(quorum_number)`` - Gets the current aggregated public key for a quorum

**Event Querying and Historical Data:**

- ``query_existing_registered_operator_sockets(start_block, stop_block, block_range)`` - Queries operator socket update events within a block range
- ``query_existing_registered_operator_pubkeys(start_block, stop_block, block_range)`` - Queries operator public key registration events within a block range

**Signature Verification Support:**

- ``get_check_signatures_indices(reference_block_number, quorum_numbers, non_signer_operator_ids)`` - Gets the indices needed for efficient signature verification, used in off-chain signature aggregation

**Access Control and Ownership:**

- ``get_registry_coordinator_owner()`` - Gets the owner address of the registry coordinator contract
- ``is_registry_coordinator_owner(address)`` - Checks if a given address is the registry coordinator owner
- ``can_satisfy_only_coordinator_owner_modifier(address)`` - Checks if an address can satisfy owner-only function modifiers

eigensdk.chainio.clients.avsregistry.writer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The AvsRegistryWriter class provides write operations for AVS registry contracts, enabling comprehensive management of operators, quorums, strategies, and rewards within the AVS ecosystem.

**Stake Update Operations:**

- ``update_stakes_of_entire_operator_set_for_quorums(operators_per_quorum, quorum_numbers)`` - Updates stakes for complete operator sets across specified quorums
- ``update_stakes_of_operator_subset_for_all_quorums(operators)`` - Updates stakes for a subset of operators across all quorums they participate in

**Operator Management:**

- ``update_socket(socket)`` - Updates the socket (network endpoint) information for an operator
- ``eject_operator(operator_address, quorum_numbers)`` - Forcibly removes an operator from specified quorums (requires appropriate permissions)

**Quorum Creation and Configuration:**

- ``create_total_delegated_stake_quorum(operator_set_params, minimum_stake_required, strategy_params)`` - Creates a new quorum based on total delegated stake with specified parameters
- ``create_slashable_stake_quorum(operator_set_params, minimum_stake_required, strategy_params, look_ahead_period)`` - Creates a new quorum based on slashable stake with lookahead period

**Configuration Management:**

- ``set_rewards_initiator(rewards_initiator_addr)`` - Sets the address authorized to initiate rewards distributions
- ``set_slashable_stake_lookahead(quorum_number, look_ahead_period)`` - Sets the slashable stake lookahead period for a quorum
- ``set_minimum_stake_for_quorum(quorum_number, minimum_stake)`` - Sets the minimum stake requirement for participation in a quorum
- ``set_operator_set_params(quorum_number, operator_set_params)`` - Updates operator set parameters for a quorum
- ``set_churn_approver(churn_approver_address)`` - Sets the address authorized to approve operator churn
- ``set_ejector(ejector_address)`` - Sets the address authorized to eject operators from quorums
- ``set_avs(avs_address)`` - Sets the AVS contract address
- ``set_ejection_cooldown(ejection_cooldown)`` - Sets the cooldown period after operator ejection

**Strategy Management:**

- ``modify_strategy_params(quorum_number, strategy_indices, multipliers)`` - Modifies the parameters (multipliers) for existing strategies in a quorum
- ``add_strategies(quorum_number, strategy_params)`` - Adds new strategies to a quorum with their respective parameters
- ``remove_strategies(quorum_number, indices_to_remove)`` - Removes strategies from a quorum by their indices

**Metadata and Documentation:**

- ``update_avs_metadata_uri(metadata_uri)`` - Updates the metadata URI for the AVS, typically pointing to JSON metadata

**Rewards Management:**

- ``create_avs_rewards_submission(rewards_submission)`` - Creates a rewards submission for distribution to operators
- ``create_operator_directed_avs_rewards_submission(operator_directed_rewards_submissions)`` - Creates operator-directed rewards submissions allowing operators to specify reward distributions

**Access Control Verification:**

- ``is_registry_coordinator_owner(address)`` - Verifies if an address is the owner of the registry coordinator contract

