import yaml
import json
import os
from eth_account import Account
from eigensdk.chainio.clients.builder import BuildAllConfig, build_all

# Get the directory where builder.py is located
current_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(current_dir, "config", "holesky.yaml")

with open(config_path, "r") as f:
    config = yaml.load(f, Loader=yaml.BaseLoader)


cfg = BuildAllConfig(
    eth_http_url=config["eth_rpc_url"],
    registry_coordinator_addr=config["avs_registry_coordinator_address"],
    operator_state_retriever_addr=config["operator_state_retriever_address"],
    avs_name=config["avs_name"],
    prom_metrics_ip_port_address=config["eigen_metrics_ip_port_address"],
)

clients = build_all(
    config=cfg,
    config_ecdsa_private_key=config["ecdsa_private_key"],
    config_reward_coordinator=config["reward_coordinator_address"],
)
