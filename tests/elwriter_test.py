import unittest

from eigensdk._types import Operator

from config import Config


class TestELWriter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.clients = cls.config.CLIENTS
        cls.el_reader = cls.clients.el_reader
        cls.el_writer = cls.clients.el_writer

    def test_register_as_operator(self):
        operator = Operator(
            address=self.config.OPERATOR_ECDSA_ADDR,
            earnings_receiver_address=self.config.OPERATOR_ECDSA_ADDR,
            staker_opt_out_window_blocks=0,
            delegation_approver_address=self.config.ZERO_ADDR,
            metadata_url="https://test.xyz/metadata.json",
        )
        self.el_writer.register_as_operator(operator)
        result = self.el_reader.is_operator_registered(self.config.OPERATOR_ECDSA_ADDR)
        self.assertTrue(result)

    def test_update_operator_details(self):
        operator_details = self.config.DELEGATION_MANAGER.functions.operatorDetails(
            self.config.OPERATOR_ECDSA_ADDR
        ).call()
        self.assertEqual(operator_details[1], self.config.ZERO_ADDR)

        new_delegation_approver_address = "0x0000000000000000000000000000000000000001"
        operator = Operator(
            address=self.config.OPERATOR_ECDSA_ADDR,
            earnings_receiver_address=self.config.OPERATOR_ECDSA_ADDR,
            staker_opt_out_window_blocks=0,
            delegation_approver_address=new_delegation_approver_address,
            metadata_url="https://test.xyz/metadata.json",
        )
        receipt = self.el_writer.update_operator_details(operator)
        self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

        operator_details = self.config.DELEGATION_MANAGER.functions.operatorDetails(
            self.config.OPERATOR_ECDSA_ADDR
        ).call()
        self.assertEqual(operator_details[1], new_delegation_approver_address)


if __name__ == "__main__":
    unittest.main()
