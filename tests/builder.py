import os
import yaml  # type: ignore
from eigensdk.chainio.clients.builder import BuildAllConfig, build_all

# Get the directory where builder.py is located
current_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(current_dir, "config", "anvil.yaml")

with open(config_path, "r") as f:
    config = yaml.load(f, Loader=yaml.BaseLoader)


cfg = BuildAllConfig(
    eth_http_url=config["eth_rpc_url"],
    avs_name="incredible-squaring",
    registry_coordinator_addr=config["avs_registry_coordinator_address"],
    operator_state_retriever_addr=config["operator_state_retriever_address"],
    rewards_coordinator_addr=config["rewards_coordinator_address"],
    permission_controller_addr=config["permission_controller_address"],
    service_manager_addr=config["service_manager_address"],
    allocation_manager_addr=config["allocation_manager_address"],
    delegation_manager_addr=config["delegation_manager_address"],
)
clients_array = []
for i in range(3):
    clients_array.append(build_all(cfg, config["ecdsa_private_key_{}".format(i + 1)]))

clients = clients_array[0]
