import logging
import os
from web3 import Web3
from dotenv import load_dotenv
from eth_account import Account
from eth_typing import Address

load_dotenv()


class Config:
    OPERATOR_ECDSA_PRIVATE_KEY: str = os.getenv("OPERATOR_ECDSA_PRIVATE_KEY", "")
    OPERATOR_ECDSA_ADDR: Address = Account.from_key(OPERATOR_ECDSA_PRIVATE_KEY)._address
    OPERATOR_BLS_PRIVATE_KEY: str = os.getenv("OPERATOR_BLS_PRIVATE_KEY", "")
    ETH_HTTP_URL: str = os.getenv("ETH_HTTP_URL", "")
    ETH_WS_URL: str = os.getenv("ETH_WS_URL", "")
    AVS_NAME: str = os.getenv("AVS_NAME", "")
    REGISTRY_COORDINATOR_ADDR: Address = Web3.to_checksum_address(
        os.getenv("REGISTRY_COORDINATOR_ADDR", "")
    )
    OPERATOR_STATE_RETRIEVER_ADDR: Address = Web3.to_checksum_address(
        os.getenv("OPERATOR_STATE_RETRIEVER_ADDR", "")
    )
    STRATEGY_ADDR: Address = Web3.to_checksum_address(os.getenv("STRATEGY_ADDR", ""))
    SERVICE_MANAGER_ADDR: Address = Web3.to_checksum_address(
        os.getenv("SERVICE_MANAGER_ADDR", "")
    )

    @staticmethod
    def get_logger(name: str = "test_logger") -> logging.Logger:
        logger = logging.getLogger(name)
        if not logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter("\n%(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        return logger

    @staticmethod
    def gen_random_salt() -> bytes:
        return os.urandom(32)
