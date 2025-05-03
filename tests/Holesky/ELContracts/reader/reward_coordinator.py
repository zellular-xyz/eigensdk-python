from tests.builder import holesky_el_reader
from eth_typing import Address


def test_get_distribution_roots_length():
    return holesky_el_reader.get_distribution_roots_length()


def test_curr_rewards_calculation_end_timestamp():
    return holesky_el_reader.curr_rewards_calculation_end_timestamp()


def test_get_current_claimable_distribution_root():
    return holesky_el_reader.get_current_claimable_distribution_root()


# revert
def test_get_root_index_from_hash():

    return holesky_el_reader.get_root_index_from_hash(root_hash=b"\x00" * 32)


def test_get_cumulative_claimed():
    return holesky_el_reader.get_cumulative_claimed(
        earner=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        token=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_get_operator_avs_split():
    return holesky_el_reader.get_operator_avs_split(
        operator=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"),
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
    )


def test_get_operator_pi_split():
    return holesky_el_reader.get_operator_pi_split(
        operator=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_operator_set_split():
    operator_set = {"Avs": Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"), "Id": 1}
    return holesky_el_reader.get_operator_set_split(
        operator=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792"), operator_set=operator_set
    )


def test_get_curr_rewards_calculation_end_timestamp():
    return holesky_el_reader.get_curr_rewards_calculation_end_timestamp()


def test_get_rewards_updater():
    return holesky_el_reader.get_rewards_updater()


def test_get_default_operator_split_bips():
    return holesky_el_reader.get_default_operator_split_bips()


def test_get_claimer_for():
    return holesky_el_reader.get_claimer_for(
        earner=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_submission_nonce():
    return holesky_el_reader.get_submission_nonce(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e")
    )


def test_get_is_avs_rewards_submission_hash():
    return holesky_el_reader.get_is_avs_rewards_submission_hash(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        hash=b"\x00" * 32,  # Sample hash (32 bytes of zeros)
    )


def test_get_is_rewards_submission_for_all_hash():
    return holesky_el_reader.get_is_rewards_submission_for_all_hash(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        hash=b"\x00" * 32,  # Sample hash (32 bytes of zeros)
    )


def test_get_is_rewards_for_all_submitter():
    return holesky_el_reader.get_is_rewards_for_all_submitter(
        submitter=Address("0x3D3534BFf2cB9cB174eBF7DF9de6386E881d1792")
    )


def test_get_is_rewards_submission_for_all_earners_hash():
    return holesky_el_reader.get_is_rewards_submission_for_all_earners_hash(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        hash=b"\x00" * 32,  # Sample hash (32 bytes of zeros)
    )


def test_get_is_operator_directed_avs_rewards_submission_hash():
    return holesky_el_reader.get_is_operator_directed_avs_rewards_submission_hash(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        hash=b"\x00" * 32,  # Sample hash (32 bytes of zeros)
    )


def test_get_is_operator_directed_operator_set_rewards_submission_hash():
    return holesky_el_reader.get_is_operator_directed_operator_set_rewards_submission_hash(
        avs=Address("0x5FdD6a71a3C88111474C812Ca6d60942d7923C1e"),
        hash=b"\x00" * 32,  # Sample hash (32 bytes of zeros)
    )


def test_get_calculation_interval_seconds():
    return holesky_el_reader.get_calculation_interval_seconds()


def test_get_max_rewards_duration():
    return holesky_el_reader.get_max_rewards_duration()


def test_get_max_retroactive_length():
    return holesky_el_reader.get_max_retroactive_length()


def test_get_max_future_length():
    return holesky_el_reader.get_max_future_length()


def test_get_genesis_rewards_timestamp():
    return holesky_el_reader.get_genesis_rewards_timestamp()


def test_get_activation_delay():
    return holesky_el_reader.get_activation_delay()
