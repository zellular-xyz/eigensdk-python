import unittest
import time
from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
from config import Config
from eigensdk._types import Operator
from web3.contract.contract import Contract


class TestELReader(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.logger = cls.config.get_logger()

    def setUp(self):
        cfg = BuildAllConfig(
            eth_http_url=self.config.ETH_HTTP_URL,
            eth_ws_url=self.config.ETH_WS_URL,
            avs_name=self.config.AVS_NAME,
            registry_coordinator_addr=self.config.REGISTRY_COORDINATOR_ADDR,
            operator_state_retriever_addr=self.config.OPERATOR_STATE_RETRIEVER_ADDR,
            prom_metrics_ip_port_address="",
        )
        self.clients = build_all(
            cfg, self.config.OPERATOR_ECDSA_PRIVATE_KEY, self.logger
        )
        self.el_reader = self.clients.el_reader

    def test_is_operator_registered(self):
        """Test if an operator is registered."""
        result = self.el_reader.is_operator_registered(self.config.OPERATOR_ECDSA_ADDR)
        self.logger.debug(f"{self.test_is_operator_registered.__doc__} => {result}")
        self.assertTrue(result)

    def test_get_operator_details(self):
        """Test getting operator details."""
        result = self.el_reader.get_operator_details(self.config.OPERATOR_ECDSA_ADDR)
        self.logger.debug(f"{self.test_get_operator_details.__doc__} => {result}")
        self.assertIsInstance(
            result, Operator, "Result should be an instance of Operator"
        )
        self.assertEqual(result.address, self.config.OPERATOR_ECDSA_ADDR)
        self.assertEqual(
            result.earnings_receiver_address, self.config.OPERATOR_ECDSA_ADDR
        )

    def test_get_strategy_and_underlying_token(self):
        """Test getting strategy and underlying token."""
        result = self.el_reader.get_strategy_and_underlying_token(
            self.config.STRATEGY_ADDR
        )
        self.logger.debug(
            f"{self.test_get_strategy_and_underlying_token.__doc__} => {result}"
        )
        self.assertIsInstance(result, tuple, "Result should be a tuple")
        self.assertIsInstance(result[0], Contract, "First element should be a Contract")
        self.assertIsInstance(result[1], str, "Second element should be a string")
        self.assertTrue(result[1], "Underlying token address should not be empty")

    def test_get_strategy_and_underlying_erc20_token(self):
        """Test getting strategy and underlying ERC20 token."""
        result = self.el_reader.get_strategy_and_underlying_erc20_token(
            self.config.STRATEGY_ADDR
        )
        self.logger.debug(
            f"{self.test_get_strategy_and_underlying_erc20_token.__doc__} => {result}"
        )
        self.assertIsInstance(result, tuple, "Result should be a tuple")
        self.assertIsInstance(result[0], Contract, "First element should be a Contract")
        self.assertIsInstance(
            result[1], Contract, "Second element should be a Contract"
        )
        self.assertIsInstance(
            result[2], str, "Third element should be an Address (string)"
        )
        self.assertTrue(result[2], "Underlying token address should not be empty")

    def test_service_manager_can_slash_operator_until_block(self):
        """Test if service manager can slash operator until a specific block."""
        result = self.el_reader.service_manager_can_slash_operator_until_block(
            self.config.OPERATOR_ECDSA_ADDR, self.config.SERVICE_MANAGER_ADDR
        )
        self.logger.debug(
            f"{self.test_service_manager_can_slash_operator_until_block.__doc__} => {result}"
        )
        self.assertIsInstance(result, int, "Result should be an integer")

    def test_operator_is_frozen(self):
        """Test if an operator is frozen."""
        result = self.el_reader.operator_is_frozen(self.config.OPERATOR_ECDSA_ADDR)
        self.logger.debug(f"{self.test_operator_is_frozen.__doc__} => {result}")
        self.assertIsInstance(result, bool, "Result should be a boolean")

    def test_get_operator_shares_in_strategy(self):
        """Test getting operator shares in a strategy."""
        result = self.el_reader.get_operator_shares_in_strategy(
            self.config.OPERATOR_ECDSA_ADDR, self.config.STRATEGY_ADDR
        )
        self.logger.debug(
            f"{self.test_get_operator_shares_in_strategy.__doc__} => {result}"
        )
        self.assertIsInstance(result, int, "Result should be an integer")

    def test_calculate_delegation_approval_digest_hash(self):
        """Test calculating delegation approval digest hash."""
        result = self.el_reader.calculate_delegation_approval_digest_hash(
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.gen_random_salt(),
            int(time.time()) + 3600,
        )
        self.logger.debug(
            f"{self.test_calculate_delegation_approval_digest_hash.__doc__} => {result}"
        )
        self.assertIsInstance(result, bytes, "Result should be bytes")
        self.assertTrue(result, "Result should not be empty")

    def test_calculate_operator_avs_registration_digest_hash(self):
        """Test calculating operator AVS registration digest hash."""
        result = self.el_reader.calculate_operator_avs_registration_digest_hash(
            self.config.OPERATOR_ECDSA_ADDR,
            self.config.SERVICE_MANAGER_ADDR,
            self.config.gen_random_salt(),
            int(time.time()) + 3600,
        )
        self.logger.debug(
            f"{self.test_calculate_operator_avs_registration_digest_hash.__doc__} => {result}"
        )
        self.assertIsInstance(result, bytes, "Result should be bytes")
        self.assertTrue(result, "Result should not be empty")


if __name__ == "__main__":
    unittest.main()
