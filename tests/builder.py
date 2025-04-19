import os
from dotenv import load_dotenv

from eigensdk.chainio.clients.builder import BuildAllConfig

# Load environment variables from both .env files
load_dotenv()
load_dotenv(".env.contract")

# Create a BuildAllConfig object with required parameters from env variables
config = BuildAllConfig(
    eth_http_url=os.getenv("ETH_HTTP_URL"),
    registry_coordinator_addr=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    operator_state_retriever_addr=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR"),
    avs_name=os.getenv("AVS_NAME"),
    prom_metrics_ip_port_address=os.getenv("PROM_METRICS_IP_PORT_ADDRESS"),
)

# Get sender/operator address and private key from env variables
SENDER_ADDRESS = os.getenv("SENDER_ADDRESS")
PRIVATE_KEY = os.getenv("OPERATOR_ECDSA_PRIVATE_KEY")

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
    sender_address=SENDER_ADDRESS,
    private_key=PRIVATE_KEY,
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
    sender_address=SENDER_ADDRESS,
    private_key=PRIVATE_KEY,
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
    sender_address=SENDER_ADDRESS,
    private_key=PRIVATE_KEY,
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR"),
    operator_state_retriever=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR"),
    service_manager=os.getenv("SERVICE_MANAGER_ADDR"),
    service_manager_addr=os.getenv("SERVICE_MANAGER_ADDR"),
    stake_registry=os.getenv("STAKE_REGISTRY_ADDR"),
    bls_apk_registry=os.getenv("BLS_APK_REGISTRY_ADDR"),
    el_chain_reader=el_reader,
)


print(f"EL Reader initialized: {el_reader}")
print(f"EL Writer initialized: {el_writer}")
print(f"AVS Registry Reader initialized: {avs_registry_reader}")
print(f"AVS Registry Writer initialized: {avs_registry_writer}")
