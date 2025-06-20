.. _eigensdk.types:

eigensdk.types
==============

This module defines the core data structures and types used throughout the EigenSDK Python library. These dataclasses provide type-safe representations of various EigenLayer entities and operations.

Core Data Types
~~~~~~~~~~~~~~~

.. py:class:: eigensdk.types_.Operator

    Represents an EigenLayer operator with their configuration and metadata.

    :param address: The blockchain address of the operator.
    :param earnings_receiver_address: Address that receives earnings from operator activities.
    :param delegation_approver_address: Address that can approve delegations to this operator.
    :param staker_opt_out_window_blocks: Number of blocks for the staker opt-out window.
    :param allocation_delay: Delay in blocks for allocation changes.
    :param metadata_url: URL pointing to operator metadata (optional).


.. py:class:: eigensdk.types_.OperatorPubkeys

    Contains the BLS public keys for an operator.

    :param g1_pub_key: The G1 public key point.
    :param g2_pub_key: The G2 public key point.

.. py:class:: eigensdk.types_.OperatorInfo

    Contains operator information including socket and public keys.

    :param socket: Network socket information for the operator.
    :param pub_keys: OperatorPubkeys object containing the operator's BLS public keys.

.. py:class:: eigensdk.types_.OperatorStateRetrieverOperator

    Represents operator data retrieved from the OperatorStateRetriever contract.

    :param operator: The operator's blockchain address.
    :param operator_id: Unique identifier for the operator as bytes.
    :param stake: The operator's stake amount.


.. py:class:: eigensdk.types_.OperatorAvsState

    Represents the state of an operator within an AVS.

    :param operator_id: Unique identifier for the operator.
    :param operator_info: OperatorInfo containing socket and public key data.
    :param stake_per_quorum: Dictionary mapping quorum numbers to stake amounts.
    :param block_number: Block number at which this state was captured.

.. py:class:: eigensdk.types_.QuorumAvsState

    Represents the state of a quorum within an AVS.

    :param quorum_number: The quorum identifier.
    :param total_stake: Total stake in this quorum.
    :param agg_pub_key_g1: Aggregated G1 public key for the quorum.
    :param block_number: Block number at which this state was captured.

Registry Types
~~~~~~~~~~~~~~

.. py:class:: eigensdk.types_.OperatorStateRetrieverCheckSignaturesIndices

    Contains indices required for signature verification operations.

    :param non_signer_quorum_bitmap_indices: Indices for non-signer quorum bitmaps.
    :param quorum_apk_indices: Indices for quorum aggregate public keys.
    :param total_stake_indices: Indices for total stake calculations.
    :param non_signer_stake_indices: Nested list of indices for non-signer stakes.

.. py:class:: eigensdk.types_.StakeRegistryTypesStrategyParams

    Parameters for strategies in the stake registry.

    :param strategy: The strategy contract address.
    :param multiplier: Multiplier applied to this strategy.

.. py:class:: eigensdk.types_.StakeRegistryTypesStakeUpdate

    Represents a stake update event in the registry.

    :param update_block_number: Block number when the update occurred.
    :param next_update_block_number: Block number of the next update.
    :param stake: The stake amount after the update.

.. py:class:: eigensdk.types_.BLSApkRegistryTypesApkUpdate

    Represents an aggregate public key update in the BLS registry.

    :param apk_hash: Hash of the aggregate public key.
    :param update_block_number: Block number when the update occurred.
    :param next_update_block_number: Block number of the next update.

Task Processing Types
~~~~~~~~~~~~~~~~~~~~~

.. py:class:: eigensdk.types_.SignedTaskResponseDigest

    Represents a signed response to a task.

    :param task_response: The task response data.
    :param bls_signature: BLS signature for the response.
    :param operator_id: ID of the operator that signed the response.

