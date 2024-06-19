import unittest

from eigensdk._types import (
    OperatorStateRetrieverCheckSignaturesIndices,
    OperatorStateRetrieverOperator,
)

from config import Config


class TestAvsRegistryReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.clients = cls.config.CLIENTS
        cls.el_reader = cls.clients.el_reader
        cls.avs_registry_reader = cls.clients.avs_registry_reader
        cls.eth_http_client = cls.clients.avs_registry_reader.eth_http_client

    def test_get_quorum_count(self):
        result = self.avs_registry_reader.get_quorum_count()
        self.assertIsInstance(result, int, "Result should be an integer")
        self.assertEqual(1, 1)

    def test_get_operators_stake_in_quorums_at_current_block(self):
        result = (
            self.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(
                [0]
            )
        )
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], list)
        self.assertIsInstance(result[0][0], OperatorStateRetrieverOperator)
        self.assertEqual(result[0][0].operator, self.config.OPERATOR_ECDSA_ADDR)

    def test_get_operators_stake_in_quorums_at_block(self):
        block_number = self.eth_http_client.eth.block_number
        result = self.avs_registry_reader.get_operators_stake_in_quorums_at_block(
            [0], block_number
        )
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], list)
        self.assertIsInstance(result[0][0], OperatorStateRetrieverOperator)
        self.assertEqual(result[0][0].operator, self.config.OPERATOR_ECDSA_ADDR)

    def test_get_operator_addrs_in_quorums_at_current_block(self):
        result = (
            self.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block([0])
        )
        self.assertIsInstance(result, list)
        self.assertIsInstance(result[0], list)
        self.assertEqual(result[0][0], self.config.OPERATOR_ECDSA_ADDR)

    def test_get_operators_stake_in_quorums_of_operator_at_block(self):
        operator_id = self.avs_registry_reader.get_operator_id(
            self.config.OPERATOR_ECDSA_ADDR
        )
        latest_block = self.eth_http_client.eth.block_number
        result = self.avs_registry_reader.get_operators_stake_in_quorums_of_operator_at_block(
            operator_id,
            latest_block,
        )
        self.assertIsInstance(result, tuple)
        self.assertIsInstance(result[0], list)
        self.assertIsInstance(result[1], list)

    def test_get_operator_stake_in_quorums_of_operator_at_current_block(self):
        operator_id = self.avs_registry_reader.get_operator_id(
            self.config.OPERATOR_ECDSA_ADDR
        )
        result = self.avs_registry_reader.get_operator_stake_in_quorums_of_operator_at_current_block(
            operator_id
        )
        self.assertIsInstance(result, dict)

    def test_get_check_signatures_indices(self):
        latest_block = self.eth_http_client.eth.block_number
        result = self.avs_registry_reader.get_check_signatures_indices(
            latest_block, [0], []
        )
        self.assertIsInstance(result, OperatorStateRetrieverCheckSignaturesIndices)

    def test_get_operator_id(self):
        result = self.avs_registry_reader.get_operator_id(
            self.config.OPERATOR_ECDSA_ADDR
        )
        self.assertIsInstance(result, bytes)

    def test_get_operator_from_id(self):
        operator_id = self.avs_registry_reader.get_operator_id(
            self.config.OPERATOR_ECDSA_ADDR
        )
        result = self.avs_registry_reader.get_operator_from_id(operator_id)
        self.assertEqual(result, self.config.OPERATOR_ECDSA_ADDR)

    def test_is_operator_registered(self):
        result = self.avs_registry_reader.is_operator_registered(
            self.config.OPERATOR_ECDSA_ADDR
        )
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
