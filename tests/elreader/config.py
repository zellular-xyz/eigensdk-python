import logging
import os
from dotenv import load_dotenv
from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
from eigensdk.contracts import ABIs
from eigensdk.crypto.bls.attestation import KeyPair
from eth_account import Account
from eth_typing import Address
from web3 import Web3

# Load environment variables from .env file
load_dotenv()


class Config:
    # Zero Address
    ZERO_ADDR = "0x0000000000000000000000000000000000000000"

    # Operator ECDSA Private Key & Address
    OPERATOR_ECDSA_PRIVATE_KEY: str = os.getenv("OPERATOR_ECDSA_PRIVATE_KEY", "0x0")
    OPERATOR_ECDSA_ADDR: Address = Account.from_key(OPERATOR_ECDSA_PRIVATE_KEY)._address

    # Operator ID
    OPERATOR_ID = Web3.to_bytes(hexstr=os.getenv("OPERATOR_ID", "0x0"))

    # Operator BLS Private Key & KeyPair
    OPERATOR_BLS_PRIVATE_KEY: str = hex(int(os.getenv("OPERATOR_BLS_PRIVATE_KEY", "0")))
    BLS_KEY_PAIR: KeyPair = KeyPair.from_string(OPERATOR_BLS_PRIVATE_KEY)

    # Web3 Provider
    ETH_HTTP_URL: str = os.getenv("ETH_HTTP_URL", "http://localhost:8545")
    WEB3 = Web3(Web3.HTTPProvider(ETH_HTTP_URL))

    # AVS Configuration
    AVS_NAME: str = os.getenv("AVS_NAME", "")

    # Contract Addresses
    CONTRACT_ADDRESSES = {
        "eigen_layer_proxy_admin": Web3.to_checksum_address(
            "0x5FbDB2315678afecb367f032d93F642f64180aa3"
        ),
        "eigen_layer_pauser_reg": Web3.to_checksum_address(
            "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
        ),
        "delegation_manager": Web3.to_checksum_address(
            "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        ),
        "avs_directory": Web3.to_checksum_address(
            "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"
        ),
        "allocation_manager": Web3.to_checksum_address(
            "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6"
        ),
        "permission_controller": Web3.to_checksum_address(
            "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"
        ),
        "strategy_manager": Web3.to_checksum_address(
            "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
        ),
        "rewards_coordinator": Web3.to_checksum_address(
            "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853"
        ),
    }

    # Logger Setup
    LOGGER = logging.getLogger("test_logger")
    handler = logging.StreamHandler()
    formatter = logging.Formatter("\n%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.DEBUG)

    # EigenLayer SDK Client Configuration
    CFG = BuildAllConfig(
        eth_http_url=ETH_HTTP_URL,
        avs_name=AVS_NAME,
        registry_coordinator_addr=CONTRACT_ADDRESSES["delegation_manager"],
        operator_state_retriever_addr=CONTRACT_ADDRESSES["avs_directory"],
        prom_metrics_ip_port_address=os.getenv(
            "PROM_METRICS_IP_PORT_ADDRESS", "localhost:9090"
        ),
    )
    CLIENTS = build_all(CFG, OPERATOR_ECDSA_PRIVATE_KEY, LOGGER)

    # Contract Instances
    SERVICE_MANAGER_ADDR = CLIENTS.avs_registry_writer.service_manager_addr
    SERVICE_MANAGER = WEB3.eth.contract(
        address=SERVICE_MANAGER_ADDR, abi=ABIs.SERVICE_MANAGER
    )

    STRATEGY_MANAGER_ADDR = CLIENTS.el_reader.strategy_manager.address
    STRATEGY_MANAGER = CLIENTS.el_reader.strategy_manager

    DELEGATION_MANAGER_ADDR = CLIENTS.el_reader.delegation_manager.address
    DELEGATION_MANAGER = CLIENTS.el_reader.delegation_manager

    REGISTRY_COORDINATOR = CLIENTS.avs_registry_reader.registry_coordinator

    STRATEGY = WEB3.eth.contract(
        address=CONTRACT_ADDRESSES["strategy_manager"], abi=ABIs.STRATEGY
    )

    @staticmethod
    def gen_random_salt() -> bytes:
        """Generate a random 32-byte salt."""
        return os.urandom(32)
