import pytest
from web3 import Web3
from web3.exceptions import ContractLogicError
from typing import cast
from eth_typing import Address

from eigensdk.crypto.bls.attestation import G1Point, G2Point
from tests.builder import clients, config


def test_get_quorum_count():
    quorum_count = clients.avs_registry_reader.get_quorum_count()
    assert isinstance(quorum_count, int)
    print(f"Quorum count: {quorum_count}")


def test_get_operators_stake_in_quorums_at_current_block():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
        quorum_numbers
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
    print(f"Operators stake in quorums at current block: {result}")


def test_get_operators_stake_in_quorums_at_block():
    quorum_numbers = [0]
    block_number = clients.eth_http_client.eth.block_number
    result = clients.avs_registry_reader.get_operators_stake_in_quorums_at_block(
        quorum_numbers, block_number
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
    print(f"Operators stake in quorums at block {block_number}: {result}")


def test_get_operator_addrs_in_quorums_at_current_block():
    quorum_numbers = [0]
    result = clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block(
        quorum_numbers
    )
    assert isinstance(result, list)
    for quorum_operators in result:
        assert isinstance(quorum_operators, list)
    print(f"Operator addresses in quorums at current block: {result}")


def test_get_operators_stake_in_quorums_of_operator_at_block():
    operator_ids = [1, 2]  # Multiple operator IDs now supported
    block_number = clients.eth_http_client.eth.block_number

    result = clients.avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
        operator_ids, block_number
    )
    print(f"Result: {result}")
    assert isinstance(result, tuple) and len(result) == 2
    quorum_ids_result, stakes_result = result

    if not quorum_ids_result:
        print("No quorums found for operator — skipping detailed assertions.")
        return

    assert isinstance(quorum_ids_result, list)
    assert all(isinstance(qid, int) for qid in quorum_ids_result)

    assert isinstance(stakes_result, list)
    assert all(isinstance(s, list) for s in stakes_result)
    for stake_list in stakes_result:
        for stake in stake_list:
            assert hasattr(stake, "operatorId")
            assert hasattr(stake, "stake")
            assert hasattr(stake, "isRegistered")

    print(f"Operator ID: {operator_ids[0]} → Quorum IDs: {quorum_ids_result}")
    print(f"Stakes at block {block_number}: {stakes_result}")


def test_weight_of_operator_for_quorum():
    quorum_number = 0
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.weight_of_operator_for_quorum(quorum_number, operator_addr)
    assert result is None or isinstance(result, int)
    print(f"Weight of operator {operator_addr} for quorum {quorum_number}: {result}")


def test_strategy_params_length():
    quorum_number = 0
    result = clients.avs_registry_reader.strategy_params_length(
        quorum_number
    )  # Verify the result is an integer or None
    assert result is None or isinstance(result, int)
    print(f"Strategy params length for quorum {quorum_number}: {result}")


def test_strategy_params_by_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.strategy_params_by_index(quorum_number, index)
    assert result is None or isinstance(result, tuple)
    print(f"Strategy params for quorum {quorum_number} at index {index}: {result}")


def test_get_stake_history_length():
    operator_id = 1
    quorum_number = 0
    stake_history_length = clients.avs_registry_reader.get_stake_history_length(
        operator_id, quorum_number
    )
    assert isinstance(stake_history_length, int), "Stake history length must be an integer"
    assert stake_history_length >= 0, "Stake history length must be non-negative"
    print(
        f"Stake history length for operator {operator_id} in quorum {quorum_number}: {stake_history_length}"
    )


def test_get_stake_history():
    operator_id = 1  # Replace with a valid operator ID
    quorum_number = 0  # Replace with a valid quorum number

    stake_history = clients.avs_registry_reader.get_stake_history(operator_id, quorum_number)

    assert isinstance(stake_history, list), "Expected stake history to be a list"

    for update in stake_history:
        assert hasattr(update, "blockNumber")
        assert hasattr(update, "stake")
        assert hasattr(update, "isRegistered")

    print(f"Stake history for operator {operator_id} in quorum {quorum_number}:")
    for entry in stake_history:
        print(
            f"  Block {entry.block_number} - Stake: {entry.stake} - Registered: {entry.is_registered}"
        )


def test_get_latest_stake_update():
    operator_id = 1
    quorum_number = 0
    latest_update = clients.avs_registry_reader.get_latest_stake_update(operator_id, quorum_number)
    print(latest_update)
    assert latest_update is not None, "Expected a stake update, got None"



def test_get_stake_update_at_index():
    operator_id = 1
    quorum_number = 0
    history_length = clients.avs_registry_reader.get_stake_history_length(
        operator_id, quorum_number
    )
    assert isinstance(history_length, int)
    if history_length <= 0:
        print(f"No stake updates available for operator {operator_id} in quorum {quorum_number}")
        return
    index = history_length - 1
    stake_update = clients.avs_registry_reader.get_stake_update_at_index(
        operator_id, quorum_number, index
    )
    assert stake_update is not None
    assert hasattr(stake_update, "blockNumber")
    assert hasattr(stake_update, "stake")
    assert hasattr(stake_update, "isRegistered")
    print(f"Stake update at index {index} for operator {operator_id} in quorum {quorum_number}:")
    print(f"  Block: {stake_update.blockNumber}")
    print(f"  Stake: {stake_update.stake}")
    print(f"  Registered: {stake_update.isRegistered}")


def test_get_stake_at_block_number():
    operator_id = 1  # Use a valid operator ID
    quorum_number = 0  # Use a valid quorum
    block_number = clients.eth_http_client.eth.block_number  # Current block

    try:
        stake = clients.avs_registry_reader.get_stake_at_block_number(
            operator_id, quorum_number, block_number
        )

        assert isinstance(stake, int), "Stake value should be an integer"
        assert stake >= 0, "Stake should be non-negative"

        print(
            f"Stake at block {block_number} for operator {operator_id} in quorum {quorum_number}: {stake}"
        )

    except ContractLogicError as e:
        error_message = str(e)
        if "no stake update found" in error_message:
            print(
                f"Skipped: No stake update found for operator {operator_id} in quorum {quorum_number} at block {block_number}"
            )
        else:
            raise  # re-raise if it's an unexpected logic error


def test_get_stake_update_index_at_block_number():
    operator_id = 1  # Replace with a valid operator ID
    quorum_number = 0  # Replace with a valid quorum
    block_number = clients.eth_http_client.eth.block_number

    try:
        index = clients.avs_registry_reader.get_stake_update_index_at_block_number(
            operator_id, quorum_number, block_number
        )

        assert isinstance(index, int), "Returned index should be an integer"
        assert index >= 0, "Index should be non-negative"

        print(
            f"Stake update index for operator {operator_id} in quorum {quorum_number} at block {block_number}: {index}"
        )

    except ContractLogicError as e:
        error_message = str(e)
        if "no stake update found" in error_message:
            print(
                f"Skipped: No stake update found for operator {operator_id} in quorum {quorum_number} at block {block_number}"
            )
        else:
            raise


def test_get_total_stake_history_length():
    quorum_number = 0  # Replace with a valid quorum number

    total_length = clients.avs_registry_reader.get_total_stake_history_length(quorum_number)

    assert isinstance(total_length, int), "Total stake history length must be an integer"
    assert total_length >= 0, "Length must be non-negative"

    print(f"Total stake history length for quorum {quorum_number}: {total_length}")


def test_get_check_signatures_indices():
    reference_block_number = clients.eth_http_client.eth.block_number - 1  # Safe block
    quorum_numbers = [0]  # Replace with valid quorum IDs
    non_signer_operator_ids = [1]  # Replace with valid registered operator IDs

    try:
        result = clients.avs_registry_reader.get_check_signatures_indices(
            reference_block_number, quorum_numbers, non_signer_operator_ids
        )

        # Validate response structure
        assert result is not None, "Expected non-null result"
        assert hasattr(result, "quorumBitmap"), "Missing quorumBitmap"
        assert hasattr(result, "operatorIdIndices"), "Missing operatorIdIndices"

        print(f"Check Signatures Indices result at block {reference_block_number}:")
        print(f"  Quorum Bitmap: {result.quorumBitmap}")
        print(f"  Operator ID Indices: {result.operatorIdIndices}")

    except ContractLogicError as e:
        if "no bitmap update found for operatorId" in str(e):
            print(
                f"No quorum bitmap update found at block {reference_block_number} for operator(s) {non_signer_operator_ids}"
            )
            return
        else:
            raise


def test_get_current_total_stake():
    quorum_number = 0  # Replace with a known valid quorum number
    total_stake = clients.avs_registry_reader.get_current_total_stake(quorum_number)
    assert isinstance(total_stake, int), "Total stake should be an integer"
    assert total_stake >= 0, "Total stake should be non-negative"
    print(f"Current total stake for quorum {quorum_number}: {total_stake}")


def test_get_total_stake_update_at_index():
    quorum_number = 0
    total_length = clients.avs_registry_reader.get_total_stake_history_length(quorum_number)
    assert total_length is not None and total_length > 0, "No total stake updates found for the given quorum"
    index = total_length - 1  # Use latest available index
    update = clients.avs_registry_reader.get_total_stake_update_at_index(quorum_number, index)
    assert update is not None


def test_get_total_stake_at_block_number_from_index():
    quorum_number = 0
    block_number = clients.eth_http_client.eth.block_number
    index = 0
    result = clients.avs_registry_reader.get_total_stake_at_block_number_from_index(
        quorum_number, block_number, index
    )
    assert result is None or isinstance(result, int)
    print(
        f"Total stake for quorum {quorum_number} at block {block_number} from index {index}: {result}"
    )


def test_get_total_stake_indices_at_block_number():
    quorum_numbers = [0]
    block_number = clients.eth_http_client.eth.block_number

    try:
        indices = clients.avs_registry_reader.get_total_stake_indices_at_block_number(
            quorum_numbers, block_number
        )

        assert isinstance(indices, list), "Expected list of indices"
        assert all(isinstance(i, int) for i in indices)

        print(
            f"Total stake indices at block {block_number} for quorums {quorum_numbers}: {indices}"
        )

    except Exception as e:
        pytest.fail(f"get_total_stake_indices_at_block_number failed: {e}")


def test_get_minimum_stake_for_quorum():
    quorum_number = 0
    result = clients.avs_registry_reader.get_minimum_stake_for_quorum(quorum_number)
    assert result is None or isinstance(result, int)
    print(f"Minimum stake for quorum {quorum_number}: {result}")


def test_get_strategy_params_at_index():
    quorum_number = 0  # Replace with a valid quorum number
    total_stake_strategy_count = clients.avs_registry_reader.get_total_stake_history_length(
        quorum_number
    )
    assert total_stake_strategy_count is not None and (
        total_stake_strategy_count >= 1
    ), f"No strategy parameters found for quorum {quorum_number}"
    index = total_stake_strategy_count - 1  # Test latest strategy param
    strategy_param = clients.avs_registry_reader.get_strategy_params_at_index(quorum_number, index)
    assert strategy_param is not None


def test_get_strategy_per_quorum_at_index():
    quorum_number = 0
    index = 0
    result = clients.avs_registry_reader.get_strategy_per_quorum_at_index(quorum_number, index)
    assert result is None or isinstance(result, str)
    print(f"Strategy for quorum {quorum_number} at index {index}: {result}")


def test_get_stake_type_per_quorum():
    quorum_number = 0
    stake_type = clients.avs_registry_reader.get_stake_type_per_quorum(quorum_number)
    assert isinstance(stake_type, int), "Stake type should be an integer"
    assert 0 <= stake_type <= 255, "Stake type should fit within uint8 range"
    print(f"Stake type for quorum {quorum_number}: {stake_type}")


def test_get_slashable_stake_look_ahead_per_quorum():
    quorum_number = 0  # Replace with a valid quorum number
    lookahead = clients.avs_registry_reader.get_slashable_stake_look_ahead_per_quorum(quorum_number)
    assert isinstance(lookahead, int), "Lookahead value should be an integer"
    assert lookahead >= 0, "Lookahead should be non-negative"
    print(f"Slashable stake lookahead for quorum {quorum_number}: {lookahead}")


def test_get_operator_id():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.get_operator_id(cast(Address, operator_addr))
    assert isinstance(result, bytes)
    print(f"Operator ID for {operator_addr}: {result.hex()}")


def test_get_operator_from_id():
    operator_id = 1  # Use integer format for the operator ID
    address = clients.avs_registry_reader.get_operator_from_id(operator_id)
    assert address is not None, "Returned address should not be None"
    assert Web3.is_checksum_address(address), f"Invalid Ethereum address returned: {address}"
    print(f"Operator ID {operator_id} maps to address: {address}")


def test_query_registration_detail():
    operator = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.query_registration_detail(cast(Address, operator))

    assert isinstance(result, list)
    assert all(isinstance(x, bool) for x in result)

    print(f"Quorum participation bitmap for operator {operator}: {result}")


def test_get_operator_address_from_operator_id():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    operator_id = clients.avs_registry_reader.get_operator_id_from_operator_address(operator_addr)
    if operator_id is not None:
        result = clients.avs_registry_reader.get_operator_address_from_operator_id(operator_id)
        assert result is None or isinstance(result, str)
        print(f"Operator address from operator ID {operator_id.hex()}: {result}")
    else:
        print("Operator ID is None, skipping test")


def test_get_pubkey_from_operator_address():
    operator_addr = Web3.to_checksum_address(config["operator_address"])
    result = clients.avs_registry_reader.get_pubkey_from_operator_address(operator_addr)
    assert result is None or isinstance(result, G1Point)
    print(f"Public key for operator {operator_addr}: {result}")


def test_get_apk_update():
    quorum_number = 0
    index = 0
    update = clients.avs_registry_reader.get_apk_update(quorum_number, index)
    assert update is not None, "APK update should not be None"
    assert isinstance(update.apk_hash, bytes)
    assert isinstance(update.update_block_number, int)
    assert isinstance(update.next_update_block_number, int)
    print(f"APK Update for quorum {quorum_number}, index {index}:")
    print(f"  Hash: {update.apk_hash.hex()}")
    print(f"  Update Block: {update.update_block_number}")
    print(f"  Next Update Block: {update.next_update_block_number}")


def test_get_current_apk():
    quorum_number = 0
    apk = clients.avs_registry_reader.get_current_apk(quorum_number)
    assert apk is not None, "APK should not be None"
    print(f"Current APK for quorum {quorum_number}:")
    print(f"  x = {apk.x}")
    print(f"  y = {apk.y}")


def test_query_existing_registered_operator_sockets():
    result, stop_block = clients.avs_registry_reader.query_existing_registered_operator_sockets()
    assert isinstance(result, dict)
    assert isinstance(stop_block, int)
    for operator_id, socket in result.items():
        assert isinstance(operator_id, bytes)
        assert isinstance(socket, str)
    print(f"Found {len(result)} registered operator sockets up to block {stop_block}")


def test_query_existing_registered_operator_pubkeys():
    operator_addresses, operator_pubkeys, stop_block = (
        clients.avs_registry_reader.query_existing_registered_operator_pubkeys()
    )
    assert isinstance(operator_addresses, list)
    assert isinstance(operator_pubkeys, list)
    assert isinstance(stop_block, int)
    assert len(operator_addresses) == len(operator_pubkeys)
    for addr, pubkey in zip(operator_addresses, operator_pubkeys):
        assert isinstance(addr, str)
        assert hasattr(pubkey, "g1_pub_key")
        assert hasattr(pubkey, "g2_pub_key")
        assert isinstance(pubkey.g1_pub_key, G1Point)
        assert isinstance(pubkey.g2_pub_key, G2Point)
    print(
        f"Found {len(operator_addresses)} registered operator public keys up to block {stop_block}"
    )


def test_registry_coordinator_owner():
    owner = clients.avs_registry_reader.get_registry_coordinator_owner()
    assert Web3.is_address(owner), "Owner should be a valid Ethereum address"
    print(f"RegistryCoordinator owner: {owner}")
    is_owner = clients.avs_registry_reader.is_registry_coordinator_owner(owner)
    assert is_owner is True, "Owner should be verified as the owner"
    test_address = Web3.to_checksum_address("0x1234567890123456789012345678901234567890")
    can_satisfy = clients.avs_registry_reader.can_satisfy_only_coordinator_owner_modifier(
        test_address
    )
    print(f"Can address {test_address} satisfy onlyCoordinatorOwner modifier? {can_satisfy}")
