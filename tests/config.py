import logging
import os

from dotenv import load_dotenv
from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
from eigensdk.contracts import ABIs
from eigensdk.crypto.bls.attestation import KeyPair
from eth_account import Account
from eth_typing import Address
from web3 import Web3

load_dotenv()


class Config:
    ZERO_ADDR = "0x0000000000000000000000000000000000000000"
    OPERATOR_ECDSA_PRIVATE_KEY: str = os.getenv("OPERATOR_ECDSA_PRIVATE_KEY", "")
    OPERATOR_ECDSA_ADDR: Address = Account.from_key(OPERATOR_ECDSA_PRIVATE_KEY)._address
    OPERATOR_ID = Web3.to_bytes(hexstr=os.getenv("OPERATOR_ID", ""))

    OPERATOR_BLS_PRIVATE_KEY: str = os.getenv("OPERATOR_BLS_PRIVATE_KEY", "")
    BLS_KEY_PAIR: KeyPair = KeyPair()
    KeyPair.from_string(OPERATOR_BLS_PRIVATE_KEY)

    ETH_HTTP_URL: str = os.getenv("ETH_HTTP_URL", "")
    WEB3 = Web3(Web3.HTTPProvider(ETH_HTTP_URL))

    AVS_NAME: str = os.getenv("AVS_NAME", "")

    REGISTRY_COORDINATOR_ADDR: Address = Web3.to_checksum_address(
        os.getenv("REGISTRY_COORDINATOR_ADDR", "")
    )
    OPERATOR_STATE_RETRIEVER_ADDR: Address = Web3.to_checksum_address(
        os.getenv("OPERATOR_STATE_RETRIEVER_ADDR", "")
    )

    STRATEGY_ADDR: Address = Web3.to_checksum_address(os.getenv("STRATEGY_ADDR", ""))

    LOGGER = logging.getLogger("test_logger")
    handler = logging.StreamHandler()
    formatter = logging.Formatter("\n%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.DEBUG)

    CFG = BuildAllConfig(
        eth_http_url=ETH_HTTP_URL,
        avs_name=AVS_NAME,
        registry_coordinator_addr=REGISTRY_COORDINATOR_ADDR,
        operator_state_retriever_addr=OPERATOR_STATE_RETRIEVER_ADDR,
        prom_metrics_ip_port_address="",
    )
    CLIENTS = build_all(CFG, OPERATOR_ECDSA_PRIVATE_KEY, LOGGER)

    SERVICE_MANAGER_ADDR = CLIENTS.avs_registry_writer.service_manager_addr
    SERVICE_MANAGER = WEB3.eth.contract(
        address=SERVICE_MANAGER_ADDR, abi=ABIs.SERVICE_MANAGER
    )

    STRATEGY_MANAGER_ADDR = CLIENTS.el_reader.strategy_manager.address
    STRATEGY_MANAGER_ADDR = CLIENTS.el_reader.strategy_manager

    DELEGATION_MANAGER_ADDR = CLIENTS.el_reader.delegation_manager.address
    DELEGATION_MANAGER = CLIENTS.el_reader.delegation_manager

    REGISTRY_COORDINATOR = CLIENTS.avs_registry_reader.registry_coordinator

    STRATEGY = WEB3.eth.contract(address=STRATEGY_ADDR, abi=ABIs.STRATEGY)

    @staticmethod
    def gen_random_salt() -> bytes:
        return os.urandom(32)
