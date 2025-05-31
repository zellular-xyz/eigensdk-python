.. _eigensdk.types:

eigensdk.types
==============

This module defines the core data structures and types used throughout the EigenSDK Python library. These dataclasses provide type-safe representations of various EigenLayer entities and operations.

Core Data Types
~~~~~~~~~~~~~~~

.. py:class:: eigensdk._types.Operator

    Represents an EigenLayer operator with their configuration and metadata.

    :param address: The blockchain address of the operator.
    :param earnings_receiver_address: Address that receives earnings from operator activities.
    :param delegation_approver_address: Address that can approve delegations to this operator.
    :param staker_opt_out_window_blocks: Number of blocks for the staker opt-out window.
    :param allocation_delay: Delay in blocks for allocation changes.
    :param metadata_url: URL pointing to operator metadata (optional).

    .. code-block:: python

        >>> from eigensdk._types import Operator
        >>> operator = Operator(
        ...     address='0x123...',
        ...     earnings_receiver_address='0x456...',
        ...     delegation_approver_address='0x789...',
        ...     staker_opt_out_window_blocks=10,
        ...     allocation_delay=5,
        ...     metadata_url='https://example.com/metadata.json'
        ... )

.. py:class:: eigensdk._types.OperatorPubkeys

    Contains the BLS public keys for an operator.

    :param g1_pub_key: The G1 public key point.
    :param g2_pub_key: The G2 public key point.

.. py:class:: eigensdk._types.OperatorInfo

    Contains operator information including socket and public keys.

    :param socket: Network socket information for the operator.
    :param pub_keys: OperatorPubkeys object containing the operator's BLS public keys.

.. py:class:: eigensdk._types.OperatorStateRetrieverOperator

    Represents operator data retrieved from the OperatorStateRetriever contract.

    :param operator: The operator's blockchain address.
    :param operator_id: Unique identifier for the operator as bytes.
    :param stake: The operator's stake amount.

    .. code-block:: python

        >>> # Example from get_operators_stake_in_quorums_at_current_block
        >>> quorums = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([0])
        >>> operator = quorums[0][0]  # First operator in first quorum
        >>> print(f"Operator {operator.operator} has stake: {operator.stake}")

.. py:class:: eigensdk._types.OperatorAvsState

    Represents the state of an operator within an AVS.

    :param operator_id: Unique identifier for the operator.
    :param operator_info: OperatorInfo containing socket and public key data.
    :param stake_per_quorum: Dictionary mapping quorum numbers to stake amounts.
    :param block_number: Block number at which this state was captured.

.. py:class:: eigensdk._types.QuorumAvsState

    Represents the state of a quorum within an AVS.

    :param quorum_number: The quorum identifier.
    :param total_stake: Total stake in this quorum.
    :param agg_pub_key_g1: Aggregated G1 public key for the quorum.
    :param block_number: Block number at which this state was captured.

Registry Types
~~~~~~~~~~~~~~

.. py:class:: eigensdk._types.OperatorStateRetrieverCheckSignaturesIndices

    Contains indices required for signature verification operations.

    :param non_signer_quorum_bitmap_indices: Indices for non-signer quorum bitmaps.
    :param quorum_apk_indices: Indices for quorum aggregate public keys.
    :param total_stake_indices: Indices for total stake calculations.
    :param non_signer_stake_indices: Nested list of indices for non-signer stakes.

.. py:class:: eigensdk._types.StakeRegistryTypesStrategyParams

    Parameters for strategies in the stake registry.

    :param strategy: The strategy contract address.
    :param multiplier: Multiplier applied to this strategy.

.. py:class:: eigensdk._types.StakeRegistryTypesStakeUpdate

    Represents a stake update event in the registry.

    :param update_block_number: Block number when the update occurred.
    :param next_update_block_number: Block number of the next update.
    :param stake: The stake amount after the update.

.. py:class:: eigensdk._types.BLSApkRegistryTypesApkUpdate

    Represents an aggregate public key update in the BLS registry.

    :param apk_hash: Hash of the aggregate public key.
    :param update_block_number: Block number when the update occurred.
    :param next_update_block_number: Block number of the next update.

Task Processing Types
~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk._types.SignedTaskResponseDigest

    Represents a signed response to a task.

    :param task_response: The task response data.
    :param bls_signature: BLS signature for the response.
    :param operator_id: ID of the operator that signed the response.

Example Usage
~~~~~~~~~~~~~

These types are commonly used when interacting with EigenLayer contracts:

.. code-block:: python

    >>> from eigensdk._types import Operator, OperatorStateRetrieverOperator
    >>> from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    >>> 
    >>> # Create and register a new operator
    >>> operator = Operator(
    ...     address='0x1234567890123456789012345678901234567890',
    ...     earnings_receiver_address='0x1234567890123456789012345678901234567890',
    ...     delegation_approver_address='0x0000000000000000000000000000000000000000',
    ...     staker_opt_out_window_blocks=50400,  # ~7 days
    ...     allocation_delay=0,
    ...     metadata_url='https://example.com/operator-metadata.json'
    ... )
    >>> 
    >>> # Register the operator (requires proper configuration and private key)
    >>> # receipt = clients.el_writer.register_as_operator(operator)
    >>> 
    >>> # Query operators in a quorum
    >>> operators = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([0])
    >>> for op in operators[0]:  # First quorum
    ...     print(f"Operator: {op.operator}, Stake: {op.stake}") 