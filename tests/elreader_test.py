import time
import unittest

from eigensdk._types import Operator
from web3.contract.contract import Contract

from config import Config


class TestELReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.clients = cls.config.CLIENTS
        cls.el_reader = cls.clients.el_reader

    def test_is_operator_registered(self):
        result = self.el_reader.is_operator_registered(self.config.OPERATOR_ECDSA_ADDR)
        self.assertTrue(result)

    def test_get_operator_details(self):
        result = self.el_reader.get_operator_details(self.config.OPERATOR_ECDSA_ADDR)
        self.assertIsInstance(
            result, Operator, "Result should be an instance of Operator"
        )
        self.assertEqual(result.address, self.config.OPERATOR_ECDSA_ADDR)
        self.assertEqual(
            result.earnings_receiver_address, self.config.OPERATOR_ECDSA_ADDR
        )

    def test_get_strategy_and_underlying_token(self):
        result = self.el_reader.get_strategy_and_underlying_token(
            self.config.STRATEGY_ADDR
        )
        self.assertIsInstance(result, tuple, "Result should be a tuple")
        self.assertIsInstance(result[0], Contract, "First element should be a Contract")
        self.assertEqual(result[0].address, self.config.STRATEGY_ADDR)
        self.assertIsInstance(result[1], str, "Second element should be a string")
        self.assertTrue(result[1], "Underlying token address should not be empty")

    def test_get_strategy_and_underlying_erc20_token(self):
        result = self.el_reader.get_strategy_and_underlying_erc20_token(
            self.config.STRATEGY_ADDR
        )
        self.assertIsInstance(result, tuple, "Result should be a tuple")
        self.assertIsInstance(result[0], Contract, "First element should be a Contract")
        self.assertEqual(result[0].address, self.config.STRATEGY_ADDR)
        self.assertIsInstance(
            result[1], Contract, "Second element should be a Contract"
        )
        self.assertIsInstance(
            result[2], str, "Third element should be an Address (string)"
        )
        self.assertTrue(result[2], "Underlying token address should not be empty")

    def test_service_manager_can_slash_operator_until_block(self):
        result = self.el_reader.service_manager_can_slash_operator_until_block(
            self.config.OPERATOR_ECDSA_ADDR, self.config.SERVICE_MANAGER_ADDR
        )
        # TODO: check the result value
        self.assertIsInstance(result, int, "Result should be an integer")

    def test_operator_is_frozen(self):
        result = self.el_reader.operator_is_frozen(self.config.OPERATOR_ECDSA_ADDR)
        self.assertFalse(result)

    def test_get_operator_shares_in_strategy(self):
        result = self.el_reader.get_operator_shares_in_strategy(
            self.config.OPERATOR_ECDSA_ADDR, self.config.STRATEGY_ADDR
        )
        self.assertIsInstance(result, int, "Result should be an integer")

    def test_calculate_delegation_approval_digest_hash(self):
        result = self.el_reader.calculate_delegation_approval_digest_hash(
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.gen_random_salt(),
            int(time.time()) + 3600,
        )
        self.assertIsInstance(result, bytes, "Result should be bytes")
        self.assertTrue(result, "Result should not be empty")
        self.assertNotEqual(result, b"", "Result should not be an empty byte string")
        zero_hash = b"\x00" * len(result)
        self.assertNotEqual(result, zero_hash, "Result should not be a zero hash")

    def test_calculate_operator_avs_registration_digest_hash(self):
        result = self.el_reader.calculate_operator_avs_registration_digest_hash(
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.SERVICE_MANAGER_ADDR,
            self.config.gen_random_salt(),
            int(time.time()) + 3600,
        )
        self.assertIsInstance(result, bytes, "Result should be bytes")
        self.assertTrue(result, "Result should not be empty")
        self.assertNotEqual(result, b"", "Result should not be an empty byte string")
        zero_hash = b"\x00" * len(result)
        self.assertNotEqual(result, zero_hash, "Result should not be a zero hash")


if __name__ == "__main__":
    unittest.main()
