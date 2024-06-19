.. _nodeapi:

eigensdk.nodeapi
================

The NodeAPI is designed to manage and report the status of various services within an AVS node. It provides endpoints for retrieving node health, service status, and specific service details.

Setup and Initialization
------------------------

The API is initialized with the node name, semantic version, IP address and port, along with a logger for event logging. Services can be registered, updated, or deregistered dynamically.

API Endpoints
-------------

1. **Node Information**
   - **Endpoint**: ``/eigen/node``
   - **Method**: GET
   - **Description**: Returns basic information about the node, including its name and version.
   - **Response**:
    .. code-block:: json

        {
          "node_name": "ExampleNode",
          "spec_version": "v0.0.1",
          "node_version": "1.2.3"
        }

2. **Node Health**
   - **Endpoint**: ``/eigen/node/health``
   - **Method**: GET
   - **Description**: Provides the current health status of the node.
   - **Responses**:
     - 200 OK: Node is fully operational.
     - 206 Partial Content: Node is partially operational.
     - 503 Service Unavailable: Node is not operational.

3. **List Services**
   - **Endpoint**: ``/eigen/node/services``
   - **Method**: GET
   - **Description**: Lists all registered services and their current status.
   - **Response**:
    .. code-block:: json

        {
          "services": [
            {
              "id": "service1",
              "name": "Database",
              "description": "Database service handling data storage",
              "status": "Up"
            }
          ]
        }

4. **Service Health**
   - **Endpoint**: ``/eigen/node/services/{service_id}/health``
   - **Method**: GET
   - **Description**: Checks the health of a specific service by ID.
   - **Responses**:
     - 200 OK: Returns the service status.
     - 404 Not Found: Service ID not found.

Enums and Models
----------------

.. py:class:: NodeHealth

    An enumeration of node health statuses.

    - Healthy
    - PartiallyHealthy
    - Unhealthy

.. py:class:: ServiceStatus

    An enumeration of service statuses.

    - Up: Service is fully operational.
    - Down: Service is not operational.
    - Initializing: Service is in the process of starting up.

.. py:class:: NodeService

    A model describing a service managed by the node.

    :param id: Unique identifier for the service.
    :param name: Human-readable name of the service.
    :param description: Description of what the service does.
    :param status: Current status of the service from the ``ServiceStatus`` enum.

Running the API
---------------

To start the NodeAPI, simply call the ``run`` function with an instance of ``NodeAPI``. The API will begin listening for requests on the specified IP address and port.

.. code-block:: python

    if __name__ == "__main__":
        node_api = NodeAPI("ExampleNode", "1.2.3", "127.0.0.1:8000", logger)
        run(node_api)

This documentation outlines how to use the NodeAPI, the functionality of each endpoint, and how to interact with the node and its services programmatically.
