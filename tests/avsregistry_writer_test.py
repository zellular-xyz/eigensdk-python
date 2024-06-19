import time
import unittest

from config import Config


class TestAvsRegistryWriter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = Config()
        cls.clients = cls.config.CLIENTS
        cls.el_reader = cls.clients.el_reader
        cls.avs_registry_writer = cls.clients.avs_registry_writer

    def test_register_operator_in_quorum_with_avs_registry_coordinator(self):
        operator_status = self.config.REGISTRY_COORDINATOR.functions.getOperatorStatus(
            self.config.OPERATOR_ECDSA_ADDR
        ).call()
        self.assertEqual(operator_status, 0)

        receipt = self.avs_registry_writer.register_operator_in_quorum_with_avs_registry_coordinator(
            operator_ecdsa_private_key=self.config.OPERATOR_ECDSA_PRIVATE_KEY,
            operator_to_avs_registration_sig_salt=self.config.gen_random_salt(),
            operator_to_avs_registration_sig_expiry=int(time.time()) + 3600,
            bls_key_pair=self.config.BLS_KEY_PAIR,
            quorum_numbers=[0],
            socket="127.0.0.1:8080",
        )
        self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

        operator_status = self.config.REGISTRY_COORDINATOR.functions.getOperatorStatus(
            self.config.OPERATOR_ECDSA_ADDR
        ).call()
        self.assertEqual(operator_status, 1)

    def test_update_stakes_of_entire_operator_set_for_quorums(self):
        receipt = (
            self.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
                [[self.config.OPERATOR_ECDSA_ADDR]], [0]
            )
        )
        self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

    def test_update_stakes_of_operator_subset_for_all_quorums(self):
        receipt = (
            self.avs_registry_writer.update_stakes_of_operator_subset_for_all_quorums(
                [self.config.OPERATOR_ECDSA_ADDR]
            )
        )
        self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

    # def test_deregister_operator(self):
    #     receipt = self.avs_registry_writer.deregister_operator([0])
    #     self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

    def test_update_socket(self):
        new_socket = "127.0.0.1:3030"
        receipt = self.avs_registry_writer.update_socket(new_socket)
        self.assertIsNotNone(receipt, "Result should be a transaction receipt dict")

        events = self.config.REGISTRY_COORDINATOR.events.OperatorSocketUpdate().process_receipt(
            receipt
        )
        self.assertEqual(events[0]["args"]["socket"], new_socket)


if __name__ == "__main__":
    unittest.main()
