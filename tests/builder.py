import os
from dotenv import load_dotenv

from eigensdk.chainio.clients.builder import BuildAllConfig

# Load environment variables from both .env files
load_dotenv()
load_dotenv(".env.contract")

# Default addresses for testing (using actual contract addresses from .env)
DEFAULT_STRATEGY_MANAGER_ADDR = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
DEFAULT_DELEGATION_MANAGER_ADDR = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
DEFAULT_AVS_DIRECTORY_ADDR = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
DEFAULT_REGISTRY_COORDINATOR_ADDR = "0xa82fF9aFd8f496c3d6ac40E2a0F282E47488CFc9"
DEFAULT_STAKE_REGISTRY_ADDR = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
DEFAULT_SERVICE_MANAGER_ADDR = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
DEFAULT_BLS_APK_REGISTRY_ADDR = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
DEFAULT_OPERATOR_STATE_RETRIEVER_ADDR = "0x95401dc811bb5740090279Ba06cfA8fcF6113778"
DEFAULT_ALLOCATION_MANAGER_ADDR = "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
DEFAULT_PERMISSION_CONTROL_ADDR = "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"
DEFAULT_REWARDS_COORDINATOR_ADDR = "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
DEFAULT_STRATEGY_ADDR = "0x09635F643e140090A9A8Dcd712eD6285858ceBef"

# Create a BuildAllConfig object with required parameters from env variables
config = BuildAllConfig(
    eth_http_url=os.getenv("ETH_HTTP_URL", "http://anvil:8545"),
    registry_coordinator_addr=os.getenv("REGISTRY_COORDINATOR_ADDR", DEFAULT_REGISTRY_COORDINATOR_ADDR),
    operator_state_retriever_addr=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR", DEFAULT_OPERATOR_STATE_RETRIEVER_ADDR),
    avs_name=os.getenv("AVS_NAME", "test1"),
    prom_metrics_ip_port_address=os.getenv("PROM_METRICS_IP_PORT_ADDRESS", "localhost:9090"),
)

# Get sender/operator address and private key from env variables
SENDER_ADDRESS = os.getenv("SENDER_ADDRESS", "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
PRIVATE_KEY = os.getenv("OPERATOR_ECDSA_PRIVATE_KEY", "0x113d0ef74250eab659fd828e62a33ca72fcb22948897b2ed66b1fa695a8b9313")

# Build EL reader client
el_reader = config.build_el_reader_clients(
    allocation_manager=os.getenv("ALLOCATION_MANAGER_ADDR", DEFAULT_ALLOCATION_MANAGER_ADDR),
    avs_directory=os.getenv("AVS_DIRECTORY_ADDR", DEFAULT_AVS_DIRECTORY_ADDR),
    delegation_manager=os.getenv("DELEGATION_MANAGER_ADDR", DEFAULT_DELEGATION_MANAGER_ADDR),
    permission_controller=os.getenv("PERMISSION_CONTROL_ADDR", DEFAULT_PERMISSION_CONTROL_ADDR),
    reward_coordinator=os.getenv("REWARDS_COORDINATOR_ADDR", DEFAULT_REWARDS_COORDINATOR_ADDR),
    strategy_manager=os.getenv("STRATEGY_MANAGER_ADDR", DEFAULT_STRATEGY_MANAGER_ADDR),
)

# Build EL writer client
el_writer = config.build_el_writer_clients(
    sender_address=SENDER_ADDRESS,
    private_key=PRIVATE_KEY,
    allocation_manager=os.getenv("ALLOCATION_MANAGER_ADDR", DEFAULT_ALLOCATION_MANAGER_ADDR),
    avs_directory=os.getenv("AVS_DIRECTORY_ADDR", DEFAULT_AVS_DIRECTORY_ADDR),
    delegation_manager=os.getenv("DELEGATION_MANAGER_ADDR", DEFAULT_DELEGATION_MANAGER_ADDR),
    permission_controller=os.getenv("PERMISSION_CONTROL_ADDR", DEFAULT_PERMISSION_CONTROL_ADDR),
    reward_coordinator=os.getenv("REWARDS_COORDINATOR_ADDR", DEFAULT_REWARDS_COORDINATOR_ADDR),
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR", DEFAULT_REGISTRY_COORDINATOR_ADDR),
    strategy_manager=os.getenv("STRATEGY_MANAGER_ADDR", DEFAULT_STRATEGY_MANAGER_ADDR),
    strategy_manager_addr=os.getenv("STRATEGY_ADDR", DEFAULT_STRATEGY_ADDR),
    el_chain_reader=el_reader,
)

# Build AVS registry reader client
avs_registry_reader = config.build_avs_registry_reader_clients(
    sender_address=SENDER_ADDRESS,
    private_key=PRIVATE_KEY,
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR", DEFAULT_REGISTRY_COORDINATOR_ADDR),
    registry_coordinator_addr=os.getenv("REGISTRY_COORDINATOR_ADDR", DEFAULT_REGISTRY_COORDINATOR_ADDR),
    bls_apk_registry=os.getenv("BLS_APK_REGISTRY_ADDR", DEFAULT_BLS_APK_REGISTRY_ADDR),
    bls_apk_registry_addr=os.getenv("BLS_APK_REGISTRY_ADDR", DEFAULT_BLS_APK_REGISTRY_ADDR),
    operator_state_retriever=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR", DEFAULT_OPERATOR_STATE_RETRIEVER_ADDR),
    service_manager=os.getenv("SERVICE_MANAGER_ADDR", DEFAULT_SERVICE_MANAGER_ADDR),
    stake_registry=os.getenv("STAKE_REGISTRY_ADDR", DEFAULT_STAKE_REGISTRY_ADDR),
)

# Build AVS registry writer client
avs_registry_writer = config.build_avs_registry_writer_clients(
    registry_coordinator=os.getenv("REGISTRY_COORDINATOR_ADDR", DEFAULT_REGISTRY_COORDINATOR_ADDR),
    operator_state_retriever=os.getenv("OPERATOR_STATE_RETRIEVER_ADDR", DEFAULT_OPERATOR_STATE_RETRIEVER_ADDR),
    service_manager=os.getenv("SERVICE_MANAGER_ADDR", DEFAULT_SERVICE_MANAGER_ADDR),
    service_manager_addr=os.getenv("SERVICE_MANAGER_ADDR", DEFAULT_SERVICE_MANAGER_ADDR),
    stake_registry=os.getenv("STAKE_REGISTRY_ADDR", DEFAULT_STAKE_REGISTRY_ADDR),
    bls_apk_registry=os.getenv("BLS_APK_REGISTRY_ADDR", DEFAULT_BLS_APK_REGISTRY_ADDR),
    el_chain_reader=el_reader,
)


print(f"EL Reader initialized: {el_reader}")
print(f"EL Writer initialized: {el_writer}")
print(f"AVS Registry Reader initialized: {avs_registry_reader}")
print(f"AVS Registry Writer initialized: {avs_registry_writer}")
