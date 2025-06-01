import logging
from typing import Tuple

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import Address
from web3 import Web3

from eigensdk.chainio.clients.avsregistry import reader as avs_reader
from eigensdk.chainio.clients.avsregistry import writer as avs_writer
from eigensdk.chainio.clients.elcontracts import reader as el_reader
from eigensdk.chainio.clients.elcontracts import writer as el_writer
from eigensdk.contracts import ABIs


class BuildAllConfig:
    def __init__(
        self,
        eth_http_url: str,
        registry_coordinator_addr: Address,
        operator_state_retriever_addr: Address,
        rewards_coordinator_addr: Address,
        permission_controller_addr: Address,
        service_manager_addr: Address,
        allocation_manager_addr: Address,
        instant_slasher_addr: Address,
        delegation_manager_addr: Address,
        avs_name: str,
    ) -> None:

        self.eth_http_url: str = eth_http_url
        self.registry_coordinator_addr = Web3.to_checksum_address(registry_coordinator_addr)
        self.operator_state_retriever_addr = Web3.to_checksum_address(operator_state_retriever_addr)
        self.rewards_coordinator_addr = Web3.to_checksum_address(rewards_coordinator_addr)
        self.permission_controller_addr = Web3.to_checksum_address(permission_controller_addr)
        self.service_manager_addr = Web3.to_checksum_address(service_manager_addr)
        self.allocation_manager_addr = Web3.to_checksum_address(allocation_manager_addr)
        self.instant_slasher_addr = Web3.to_checksum_address(instant_slasher_addr)
        self.delegation_manager_addr = Web3.to_checksum_address(delegation_manager_addr)
        self.avs_name: str = avs_name
        self.logger: logging.Logger = logging.getLogger(__name__)

    def build_el_clients(
        self,
        ecdsa_private_key: str,
    ) -> Tuple[el_reader.ELReader, el_writer.ELWriter]:
        eth_http_client = Web3(Web3.HTTPProvider(self.eth_http_url))

        pk_wallet = Account.from_key(ecdsa_private_key)
        registry_coordinator_instance = eth_http_client.eth.contract(
            address=self.registry_coordinator_addr,
            abi=ABIs.REGISTRY_COORDINATOR_ABI,
        )
        stake_registry_addr = registry_coordinator_instance.functions.stakeRegistry().call()
        stake_registry_instance = eth_http_client.eth.contract(
            address=stake_registry_addr,
            abi=ABIs.STAKE_REGISTRY_ABI,
        )
        delegation_manager_addr = stake_registry_instance.functions.delegation().call()
        delegation_manager_instance = eth_http_client.eth.contract(
            address=delegation_manager_addr,
            abi=ABIs.DELEGATION_MANAGER_ABI,
        )
        strategy_manager_addr = delegation_manager_instance.functions.strategyManager().call()
        strategy_manager_instance = eth_http_client.eth.contract(
            address=strategy_manager_addr,
            abi=ABIs.STRATEGY_MANAGER_ABI,
        )
        service_manager = eth_http_client.eth.contract(
            address=self.service_manager_addr,
            abi=ABIs.SERVICE_MANAGER_BASE_ABI,
        )

        allocation_manager_instance = eth_http_client.eth.contract(
            address=self.allocation_manager_addr,
            abi=ABIs.ALLOCATION_MANAGER_ABI,
        )
        permission_controller_instance = eth_http_client.eth.contract(
            address=self.permission_controller_addr,
            abi=ABIs.PERMISSION_CONTROLLER_ABI,
        )

        avs_directory_addr = service_manager.functions.avsDirectory().call()
        avs_directory_instance = eth_http_client.eth.contract(
            address=avs_directory_addr,
            abi=ABIs.AVS_DIRECTORY_ABI,
        )
        rewards_coordinator_instance = eth_http_client.eth.contract(
            address=self.rewards_coordinator_addr, abi=ABIs.REWARDS_COORDINATOR_ABI
        )

        el_reader_instance = el_reader.ELReader(
            allocation_manager=allocation_manager_instance,
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=permission_controller_instance,
            reward_coordinator=rewards_coordinator_instance,
            strategy_manager=strategy_manager_instance,
            logger=self.logger,
            eth_http_client=eth_http_client,
            strategy_abi=ABIs.I_STRATEGY_ABI,
            erc20_abi=ABIs.IERC20_ABI,
        )
        el_writer_instance = el_writer.ELWriter(
            allocation_manager=allocation_manager_instance,
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=permission_controller_instance,
            reward_coordinator=rewards_coordinator_instance,
            registry_coordinator=registry_coordinator_instance,
            strategy_manager=strategy_manager_instance,
            el_chain_reader=el_reader_instance,
            logger=self.logger,
            pk_wallet=pk_wallet,
            eth_http_client=eth_http_client,
            strategy_abi=ABIs.I_STRATEGY_ABI,
            erc20_abi=ABIs.IERC20_ABI,
        )

        return el_reader_instance, el_writer_instance

    def build_avs_registry_clients(
        self,
        ecdsa_private_key: str,
        el_chain_reader: el_reader.ELReader,
    ) -> Tuple[avs_reader.AvsRegistryReader, avs_writer.AvsRegistryWriter]:
        pk_wallet = Account.from_key(ecdsa_private_key)
        eth_http_client = Web3(Web3.HTTPProvider(self.eth_http_url))
        registry_coordinator_instance = eth_http_client.eth.contract(
            address=self.registry_coordinator_addr,
            abi=ABIs.REGISTRY_COORDINATOR_ABI,
        )
        operator_state_retriever_instance = eth_http_client.eth.contract(
            address=self.operator_state_retriever_addr, abi=ABIs.OPERATOR_STATE_RETRIEVER_ABI
        )
        bls_apk_registry_addr = registry_coordinator_instance.functions.blsApkRegistry().call()
        bls_apk_registry_instance = eth_http_client.eth.contract(
            address=bls_apk_registry_addr,
            abi=ABIs.BLS_APK_REGISTRY_ABI,
        )
        service_manager_instance = eth_http_client.eth.contract(
            address=self.service_manager_addr,
            abi=ABIs.STRATEGY_MANAGER_ABI,
        )
        stake_registry_addr = registry_coordinator_instance.functions.stakeRegistry().call()
        stake_registry_instance = eth_http_client.eth.contract(
            address=stake_registry_addr,
            abi=ABIs.STAKE_REGISTRY_ABI,
        )

        avs_reader_instance = avs_reader.AvsRegistryReader(
            registry_coordinator=registry_coordinator_instance,
            registry_coordinator_addr=Address(bytes.fromhex(self.registry_coordinator_addr[2:])),
            bls_apk_registry=bls_apk_registry_instance,
            bls_apk_registry_addr=bls_apk_registry_addr,
            operator_state_retriever=operator_state_retriever_instance,
            service_manager=service_manager_instance,
            stake_registry=stake_registry_instance,
            logger=self.logger,
            eth_http_client=eth_http_client,
            pk_wallet=pk_wallet,
        )
        avs_writer_instance = avs_writer.AvsRegistryWriter(
            registry_coordinator=registry_coordinator_instance,
            operator_state_retriever=operator_state_retriever_instance,
            service_manager=service_manager_instance,
            service_manager_addr=Address(bytes.fromhex(self.service_manager_addr[2:])),
            stake_registry=stake_registry_instance,
            bls_apk_registry=bls_apk_registry_instance,
            el_reader=el_chain_reader,
            logger=self.logger,
            eth_http_client=eth_http_client,
            pk_wallet=pk_wallet,
            service_manager_abi=ABIs.SERVICE_MANAGER_BASE_ABI,
        )
        return avs_reader_instance, avs_writer_instance


class Clients:
    def __init__(
        self,
        avs_registry_reader: avs_reader.AvsRegistryReader,
        avs_registry_writer: avs_writer.AvsRegistryWriter,
        el_reader: el_reader.ELReader,
        el_writer: el_writer.ELWriter,
        eth_http_client: Web3,
        wallet: LocalAccount,
    ):
        self.avs_registry_reader = avs_registry_reader
        self.avs_registry_writer = avs_registry_writer
        self.el_reader = el_reader
        self.el_writer = el_writer
        self.eth_http_client = eth_http_client
        self.wallet = wallet


def build_all(
    config: BuildAllConfig,
    config_ecdsa_private_key: str,
) -> Clients:
    eth_http_client = Web3(Web3.HTTPProvider(config.eth_http_url))
    pk_wallet: LocalAccount = Account.from_key(config_ecdsa_private_key)

    el_reader, el_writer = config.build_el_clients(ecdsa_private_key=config_ecdsa_private_key)

    avs_reader, avs_writer = config.build_avs_registry_clients(
        ecdsa_private_key=config_ecdsa_private_key, el_chain_reader=el_reader
    )

    return Clients(
        avs_registry_reader=avs_reader,
        avs_registry_writer=avs_writer,
        el_reader=el_reader,
        el_writer=el_writer,
        eth_http_client=eth_http_client,
        wallet=pk_wallet,
    )
