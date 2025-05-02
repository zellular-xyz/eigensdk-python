import os
from dotenv import load_dotenv
from web3 import Web3
from eigensdk.chainio.clients.builder import BuildAllConfig
from eth_utils import to_checksum_address
from eth_keys import keys
from eth_utils import to_checksum_address, keccak

# Load environment variables from both .env files
load_dotenv()

# Create a BuildAllConfig object with required parameters from env variables
config = BuildAllConfig(
    eth_http_url=os.getenv("ETH_HTTP_URL"),
    registry_coordinator_addr=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    operator_state_retriever_addr=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR"),
    avs_name=os.getenv("AVS_NAME"),
    prom_metrics_ip_port_address=os.getenv("PROM_METRICS_IP_PORT_ADDRESS"),
)

holesky_config = BuildAllConfig(
    eth_http_url=os.getenv("HOLESKY_ETH_HTTP_URL"),
    registry_coordinator_addr=os.getenv("HOLESKY_REGISTRY_COORDINATOR_ADDR"),
    operator_state_retriever_addr=os.getenv("HOLESKY_OPERATOR_STATE_RETRIEVER_ADDR"),
    avs_name=os.getenv("AVS_NAME"),
    prom_metrics_ip_port_address=os.getenv("PROM_METRICS_IP_PORT_ADDRESS"),
)

# Get sender/operator address and private key from env variables
ANVIL_SENDER_ADDRESS = os.getenv("ANVIL_SENDER_ADDRESS")
ANVIL_PRIVATE_KEY = os.getenv("ANVIL_PRIVATE_KEY")

HOLESKY_SENDER_ADDRESS = os.getenv("HOLESKY_SENDER_ADDRESS")
HOLESKY_PRIVATE_KEY = os.getenv("HOLESKY_PRIVATE_KEY")


# Build EL reader client
el_reader = config.build_el_reader_clients(
    allocation_manager=os.getenv("ALLOCATION_MANAGER_ADDR"),
    avs_directory=os.getenv("AVS_DIRECTORY_ADDR"),
    delegation_manager=os.getenv("DELEGATION_MANAGER_ADDR"),
    permission_controller=os.getenv("PERMISSION_CONTROL_ADDR"),
    reward_coordinator=os.getenv("REWARDS_COORDINATOR_ADDR"),
    strategy_manager=os.getenv("STRATEGY_MANAGER_ADDR"),
)

# Build EL writer client
el_writer = config.build_el_writer_clients(
    operator_ecdsa_private_key=ANVIL_PRIVATE_KEY,
    allocation_manager=os.getenv("ALLOCATION_MANAGER_ADDR"),
    avs_directory=os.getenv("AVS_DIRECTORY_ADDR"),
    delegation_manager=os.getenv("DELEGATION_MANAGER_ADDR"),
    permission_controller=os.getenv("PERMISSION_CONTROL_ADDR"),
    reward_coordinator=os.getenv("REWARDS_COORDINATOR_ADDR"),
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    strategy_manager=os.getenv("STRATEGY_MANAGER_ADDR"),
    strategy_manager_addr=os.getenv("STRATEGY_ADDR"),
    el_chain_reader=el_reader,
)

# Build AVS registry reader client
avs_registry_reader = config.build_avs_registry_reader_clients(
    operator_ecdsa_private_key=ANVIL_PRIVATE_KEY,
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    registry_coordinator_addr=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    bls_apk_registry=os.getenv("BLS_APK_REGISTRY_ADDR"),
    bls_apk_registry_addr=os.getenv("BLS_APK_REGISTRY_ADDR"),
    operator_state_retriever=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR"),
    service_manager=os.getenv("SERVICE_MANAGER_ADDR"),
    stake_registry=os.getenv("STAKE_REGISTRY_ADDR"),
)

# Build AVS registry writer client
avs_registry_writer = config.build_avs_registry_writer_clients(
    operator_ecdsa_private_key=ANVIL_PRIVATE_KEY,
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    operator_state_retriever=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR"),
    service_manager=os.getenv("SERVICE_MANAGER_ADDR"),
    service_manager_addr=os.getenv("SERVICE_MANAGER_ADDR"),
    stake_registry=os.getenv("STAKE_REGISTRY_ADDR"),
    bls_apk_registry=os.getenv("BLS_APK_REGISTRY_ADDR"),
    el_chain_reader=el_reader,
)


# Build EL reader client
holesky_el_reader = holesky_config.build_el_reader_clients(
    allocation_manager=to_checksum_address(os.getenv("HOLESKY_ALLOCATION_MANAGER_ADDR")),
    avs_directory=to_checksum_address(os.getenv("HOLESKY_AVS_DIRECTORY_ADDR")),
    delegation_manager=to_checksum_address(os.getenv("HOLESKY_DELEGATION_MANAGER_ADDR")),
    permission_controller=to_checksum_address(os.getenv("HOLESKY_PERMISSION_CONTROL_ADDR")),
    reward_coordinator=to_checksum_address(os.getenv("HOLESKY_REWARDS_COORDINATOR_ADDR")),
    strategy_manager=to_checksum_address(os.getenv("HOLESKY_STRATEGY_MANAGER_ADDR")),
)

# Build EL writer client
holesky_el_writer = holesky_config.build_el_writer_clients(
    operator_ecdsa_private_key=HOLESKY_PRIVATE_KEY,
    allocation_manager=to_checksum_address(os.getenv("HOLESKY_ALLOCATION_MANAGER_ADDR").lower()),
    avs_directory=to_checksum_address(os.getenv("HOLESKY_AVS_DIRECTORY_ADDR").lower()),
    delegation_manager=to_checksum_address(os.getenv("HOLESKY_DELEGATION_MANAGER_ADDR").lower()),
    permission_controller=to_checksum_address(os.getenv("HOLESKY_PERMISSION_CONTROL_ADDR").lower()),
    reward_coordinator=to_checksum_address(os.getenv("HOLESKY_REWARDS_COORDINATOR_ADDR").lower()),
    registry_coordinator=to_checksum_address(os.getenv("HOLESKY_REGISTRY_COORDINATOR_ADDR").lower()),
    strategy_manager=to_checksum_address(os.getenv("HOLESKY_STRATEGY_MANAGER_ADDR").lower()),
    strategy_manager_addr=to_checksum_address(os.getenv("HOLESKY_STRATEGY_ADDR").lower()),
    el_chain_reader=holesky_el_reader,
)

# Build AVS registry reader client
holesky_avs_registry_reader = holesky_config.build_avs_registry_reader_clients(
    operator_ecdsa_private_key=HOLESKY_PRIVATE_KEY,
    registry_coordinator=to_checksum_address(os.getenv("HOLESKY_REGISTRY_COORDINATOR_ADDR").lower()),
    registry_coordinator_addr=to_checksum_address(os.getenv("HOLESKY_REGISTRY_COORDINATOR_ADDR").lower()),
    bls_apk_registry=to_checksum_address(os.getenv("HOLESKY_BLS_APK_REGISTRY_ADDR").lower()),
    bls_apk_registry_addr=to_checksum_address(os.getenv("HOLESKY_BLS_APK_REGISTRY_ADDR").lower()),
    operator_state_retriever=to_checksum_address(os.getenv("HOLESKY_OPERATOR_STATE_RETRIEVER_ADDR").lower()),
    service_manager=to_checksum_address(os.getenv("HOLESKY_SERVICE_MANAGER_ADDR").lower()),
    stake_registry=to_checksum_address(os.getenv("HOLESKY_STAKE_REGISTRY_ADDR").lower()),
)

# Build AVS registry writer client
holesky_avs_registry_writer = holesky_config.build_avs_registry_writer_clients(
    operator_ecdsa_private_key=HOLESKY_PRIVATE_KEY,
    registry_coordinator=to_checksum_address(os.getenv("HOLESKY_REGISTRY_COORDINATOR_ADDR").lower()),
    operator_state_retriever=to_checksum_address(os.getenv("HOLESKY_OPERATOR_STATE_RETRIEVER_ADDR").lower()),
    service_manager=to_checksum_address(os.getenv("HOLESKY_SERVICE_MANAGER_ADDR").lower()),
    service_manager_addr=to_checksum_address(os.getenv("HOLESKY_SERVICE_MANAGER_ADDR").lower()),
    stake_registry=to_checksum_address(os.getenv("HOLESKY_STAKE_REGISTRY_ADDR").lower()),
    bls_apk_registry=to_checksum_address(os.getenv("HOLESKY_BLS_APK_REGISTRY_ADDR").lower()),
    el_chain_reader=holesky_el_reader,
)
