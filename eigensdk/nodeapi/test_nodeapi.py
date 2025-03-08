
import unittest
from new_nodeapi import NodeApi, NodeHealth, ServiceStatus, NodeService, SPEC_SEM_VER, BASE_URL
import queue
import threading
import time

# Dummy logger to capture log messages.
class DummyLogger:
    def __init__(self):
        self.logs = []

    def info(self, msg, **kwargs):
        self.logs.append(("INFO", msg, kwargs))

    def error(self, msg, **kwargs):
        self.logs.append(("ERROR", msg, kwargs))

class TestNodeApi(unittest.TestCase):
    def setUp(self):
        # Create a dummy logger and a NodeApi instance.
        self.logger = DummyLogger()
        self.node_api = NodeApi("test_node", "v1.0", "127.0.0.1:5001", self.logger)

    def test_update_health(self):
        # Check that initial health is HEALTHY.
        self.assertEqual(self.node_api.health, NodeHealth.HEALTHY)
        # Update health and check.
        self.node_api.update_health(NodeHealth.UNHEALTHY)
        self.assertEqual(self.node_api.health, NodeHealth.UNHEALTHY)

    def test_register_new_service(self):
        self.node_api.register_new_service("1", "Service1", "Test service", ServiceStatus.UP)
        self.assertEqual(len(self.node_api.node_services), 1)
        service = self.node_api.node_services[0]
        self.assertEqual(service.id, "1")
        self.assertEqual(service.name, "Service1")
        self.assertEqual(service.description, "Test service")
        self.assertEqual(service.status, ServiceStatus.UP)

    def test_update_service_status(self):
        # Register a service.
        self.node_api.register_new_service("2", "Service2", "Another service", ServiceStatus.INITIALIZING)
        # Update its status.
        self.node_api.update_service_status("2", ServiceStatus.UP)
        service = self.node_api.node_services[0]
        self.assertEqual(service.status, ServiceStatus.UP)
        # Attempt to update a non-existing service.
        with self.assertRaises(ValueError):
            self.node_api.update_service_status("nonexistent", ServiceStatus.DOWN)

    def test_deregister_service(self):
        # Register two services.
        self.node_api.register_new_service("3", "Service3", "Service three", ServiceStatus.DOWN)
        self.node_api.register_new_service("4", "Service4", "Service four", ServiceStatus.UP)
        self.assertEqual(len(self.node_api.node_services), 2)
        # Deregister one service.
        self.node_api.deregister_service("3")
        self.assertEqual(len(self.node_api.node_services), 1)
        self.assertEqual(self.node_api.node_services[0].id, "4")
        # Attempt to deregister a non-existing service.
        with self.assertRaises(ValueError):
            self.node_api.deregister_service("nonexistent")

    def test_node_handler(self):
        # Test node_handler response.
        response, status_code = self.node_api.node_handler()
        self.assertEqual(status_code, 200)
        self.assertEqual(response["node_name"], "test_node")
        self.assertEqual(response["spec_version"], SPEC_SEM_VER)
        self.assertEqual(response["node_version"], "v1.0")

    def test_health_handler(self):
        # Default health HEALTHY -> 200.
        resp, code = self.node_api.health_handler()
        self.assertEqual(code, 200)
        # Test PARTIALLY_HEALTHY -> 206.
        self.node_api.update_health(NodeHealth.PARTIALLY_HEALTHY)
        resp, code = self.node_api.health_handler()
        self.assertEqual(code, 206)
        # Test UNHEALTHY -> 503.
        self.node_api.update_health(NodeHealth.UNHEALTHY)
        resp, code = self.node_api.health_handler()
        self.assertEqual(code, 503)

    def test_services_handler(self):
        # Initially, no services registered.
        resp, code = self.node_api.services_handler()
        self.assertEqual(code, 200)
        self.assertEqual(resp["services"], [])
        # Register a service and test.
        self.node_api.register_new_service("5", "Service5", "Service five", ServiceStatus.INITIALIZING)
        resp, code = self.node_api.services_handler()
        self.assertEqual(code, 200)
        self.assertEqual(len(resp["services"]), 1)
        self.assertEqual(resp["services"][0]["id"], "5")

    def test_service_health_handler(self):
        # Register services with different statuses.
        self.node_api.register_new_service("6", "UpService", "Up service", ServiceStatus.UP)
        self.node_api.register_new_service("7", "DownService", "Down service", ServiceStatus.DOWN)
        self.node_api.register_new_service("8", "InitService", "Initializing service", ServiceStatus.INITIALIZING)

        # Test service health for each.
        _, code = self.node_api.service_health_handler("6")
        self.assertEqual(code, 200)

        _, code = self.node_api.service_health_handler("7")
        self.assertEqual(code, 503)

        _, code = self.node_api.service_health_handler("8")
        self.assertEqual(code, 206)

        # Test unknown service returns 404.
        _, code = self.node_api.service_health_handler("nonexistent")
        self.assertEqual(code, 404)

    def test_start_method_returns_queue(self):
        # Since start() starts a Flask server, we test that it returns a queue
        err_queue = self.node_api.start()
        self.assertIsInstance(err_queue, queue.Queue)
        # Optionally, let the server run briefly and then verify no error has been enqueued.
        time.sleep(1)
        self.assertTrue(err_queue.empty())

        # Note: In real integration tests, you might use Flask's test client to hit the endpoints,
        # but here we limit ourselves to verifying that the server starts without immediate errors.

if __name__ == '__main__':
    unittest.main()

