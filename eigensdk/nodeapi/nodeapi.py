import queue
import threading
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Constants similar to Go constants
BASE_URL = "/eigen"
SPEC_SEM_VER = "v0.0.1"


# Enums for NodeHealth and ServiceStatus
class NodeHealth(Enum):
    HEALTHY = 0
    PARTIALLY_HEALTHY = 1  # Either initializing or some backing services are not healthy
    UNHEALTHY = 2


class ServiceStatus(str, Enum):
    UP = "Up"
    DOWN = "Down"
    INITIALIZING = "Initializing"


# Data class for NodeService
@dataclass
class NodeService:
    id: str
    name: str
    description: str
    status: ServiceStatus


# NodeApi class exposing a FastAPI app and a start() method for running the server
class NodeApi:
    def __init__(self, avs_node_name: str, avs_node_sem_ver: str, ip_port_addr: str, logger):
        self.avs_node_name = avs_node_name
        self.avs_node_sem_ver = avs_node_sem_ver
        self.health = NodeHealth.HEALTHY
        self.node_services: List[NodeService] = []
        self.ip_port_addr = ip_port_addr  # Expected format "host:port" e.g., "127.0.0.1:8000"
        self.logger = logger

    def update_health(self, health: NodeHealth):
        """Update the health status of the node."""
        self.health = health

    def register_new_service(
        self,
        service_id: str,
        service_name: str,
        service_description: str,
        service_status: ServiceStatus,
    ):
        """Registers a new service to the node."""
        new_service = NodeService(
            id=service_id,
            name=service_name,
            description=service_description,
            status=service_status,
        )
        self.node_services.append(new_service)

    def update_service_status(self, service_id: str, service_status: ServiceStatus):
        """
        Updates the status of a service with the given service_id.

        Raises:
            ValueError: If the service with the provided service_id is not found.
        """
        for service in self.node_services:
            if service.id == service_id:
                service.status = service_status
                return
        raise ValueError(f"Service with serviceId {service_id} not found")

    def deregister_service(self, service_id: str):
        """
        Deregisters a service by removing it from the node_services list.

        Raises:
            ValueError: If the service with the provided service_id is not found.
        """
        for index, service in enumerate(self.node_services):
            if service.id == service_id:
                del self.node_services[index]
                return
        raise ValueError(f"Service with serviceId {service_id} not found")

    def node_handler(self):
        """
        Handles GET requests for the node information endpoint.
        Mirrors https://docs.eigenlayer.xyz/eigenlayer/avs-guides/spec/api/#get-eigennode
        """
        try:
            response = {
                "node_name": self.avs_node_name,
                "spec_version": SPEC_SEM_VER,
                "node_version": self.avs_node_sem_ver,
            }
            return response, 200
        except Exception as err:
            self.logger.error("Error in node_handler", err=str(err))
            return {"error": "Internal Server Error"}, 500

    def health_handler(self):
        """
        Handles GET requests for the node health endpoint.
        Mirrors https://docs.eigenlayer.xyz/eigenlayer/avs-guides/spec/api/#get-eigennodehealth
        """
        if self.health == NodeHealth.HEALTHY:
            return {}, 200
        elif self.health == NodeHealth.PARTIALLY_HEALTHY:
            return {}, 206
        elif self.health == NodeHealth.UNHEALTHY:
            return {}, 503
        else:
            self.logger.error("Unknown health status", health=str(self.health))
            return {}, 503

    def services_handler(self):

        try:
            services = [asdict(service) for service in self.node_services]
            return {"services": services}, 200
        except Exception as err:
            self.logger.error("Error in services_handler", err=str(err))
            return {"error": "Internal Server Error"}, 500

    def service_health_handler(self, service_id: str):

        for service in self.node_services:
            if service.id == service_id:
                if service.status == ServiceStatus.UP:
                    return {}, 200
                elif service.status == ServiceStatus.DOWN:
                    return {}, 503
                elif service.status == ServiceStatus.INITIALIZING:
                    return {}, 206
                else:
                    self.logger.error("Unknown service status", serviceStatus=str(service.status))
                    return {}, 503
        # Service not found
        return {}, 404

    def get_app(self) -> FastAPI:
        """
        Returns a FastAPI app with all the necessary routes configured.
        """
        app = FastAPI()

        @app.get(BASE_URL + "/node")
        async def get_node():
            response, status_code = self.node_handler()
            return JSONResponse(content=response, status_code=status_code)

        @app.get(BASE_URL + "/node/health")
        async def get_health():
            response, status_code = self.health_handler()
            return JSONResponse(content=response, status_code=status_code)

        @app.get(BASE_URL + "/node/services")
        async def get_services():
            response, status_code = self.services_handler()
            return JSONResponse(content=response, status_code=status_code)

        @app.get(BASE_URL + "/node/services/{service_id}/health")
        async def get_service_health(service_id: str):
            response, status_code = self.service_health_handler(service_id)
            return JSONResponse(content=response, status_code=status_code)

        return app

    def start(self):
        """
        Starts the node API server using FastAPI and uvicorn in a background thread.
        Returns:
            A queue.Queue instance that will receive exceptions (if any) raised by the server.
        """
        app = self.get_app()
        host, port_str = self.ip_port_addr.split(":")
        port = int(port_str)
        err_queue = queue.Queue()

        def run_server():
            try:
                uvicorn.run(app, host=host, port=port, log_level="info")
            except Exception as e:
                err_queue.put(e)

        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        return err_queue


# Example logger for demonstration purposes
class SimpleLogger:
    def info(self, msg):
        print("[INFO]", msg)

    def error(self, msg, **kwargs):
        print("[ERROR]", msg, kwargs)
