import logging
from eth_typing import Address
from web3 import Web3
from typing import Any, Optional, Tuple
from eigensdk.chainio.clients.avsregistry import reader as avs_reader
from eigensdk.chainio.clients.avsregistry import writer as avs_writer
from eigensdk.chainio.clients.elcontracts import reader as el_reader
from eigensdk.chainio.clients.elcontracts import writer as el_writer
from eigensdk.contracts import ABIs
from eth_account.signers.local import LocalAccount
from eth_account import Account


class BuildAllConfig:
    def __init__(
        self,
        eth_http_url: str,
        registry_coordinator_addr: Address,
        operator_state_retriever_addr: Address,
        avs_name: str,
        prom_metrics_ip_port_address: str,
    ) -> None:

        self.eth_http_url: str = eth_http_url
        self.registry_coordinator_addr: Address = registry_coordinator_addr
        self.operator_state_retriever_addr: Address = operator_state_retriever_addr
        self.avs_name: str = avs_name
        self.prom_metrics_ip_port_address: str = prom_metrics_ip_port_address
        self.logger: logging.Logger = logging.getLogger(__name__)

    def build_el_clients(
        self,
        ecdsa_private_key: str,
        reward_coordinator: Address,
    ) -> Tuple[el_reader.ELReader, el_writer.ELWriter]:

        eth_http_client = Web3(Web3.HTTPProvider(self.eth_http_url))
        pk_wallet = Account.from_key(ecdsa_private_key)
        registry_coordinator_instance = eth_http_client.eth.contract(
            address=self.registry_coordinator_addr,
            abi=ABIs.REGISTRY_COORDINATOR_ABI,
        )

        stake_registry_addr = registry_coordinator_instance.functions.stakeRegistry().call()
        stake_registry = eth_http_client.eth.contract(
            address=stake_registry_addr,
            abi=ABIs.STAKE_REGISTRY_ABI,
        )

        delegation_manager_addr = stake_registry.functions.delegation().call()
        delegation_manager_instance = eth_http_client.eth.contract(
            address=delegation_manager_addr,
            abi=ABIs.DELEGATION_MANAGER_ABI,
        )

        strategy_manager_addr = delegation_manager_instance.functions.strategyManager().call()
        strategy_manager_instance = eth_http_client.eth.contract(
            address=strategy_manager_addr,
            abi=ABIs.STRATEGY_MANAGER_ABI,
        )

        # allocation_manager_addr = delegation_manager_instance.functions.allocationManager().call()
        # allocation_manager_instance = eth_http_client.eth.contract(
        #     address=allocation_manager_addr,
        #     abi=ABIs.ALLOCATION_MANAGER_ABI,
        # )

        # permission_controller_addr = delegation_manager_instance.functions.permissionController().call()
        # permission_controller_instance = eth_http_client.eth.contract(
        #     address=permission_controller_addr,
        #     abi=ABIs.PERMISSION_CONTROLLER_ABI,
        # )

        service_manager_addr = registry_coordinator_instance.functions.serviceManager().call()
        service_manager = eth_http_client.eth.contract(
            address=service_manager_addr,
            abi=ABIs.SERVICE_MANAGER_BASE_ABI,
        )
        avs_directory_addr = service_manager.functions.avsDirectory().call()
        avs_directory_instance = eth_http_client.eth.contract(
            address=avs_directory_addr,
            abi=ABIs.AVS_DIRECTORY_ABI,
        )

        # rewards_coordinator_instance = self.eth_http_client.eth.contract(
        #     address=reward_coordinator, abi=ABIs.REWARDS_COORDINATOR_ABI
        # )
        el_reader_instance = el_reader.ELReader(
            allocation_manager=None,  # allocation_manager_instance,#
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=None,  # permission_controller_instance,#
            reward_coordinator=None,  # rewards_coordinator_instance,#
            strategy_manager=strategy_manager_instance,
            logger=self.logger,
            eth_http_client=eth_http_client,
            strategy_abi=ABIs.I_STRATEGY_ABI,
            erc20_abi=ABIs.IERC20_ABI,
        )
        el_writer_instance = el_writer.ELWriter(
            allocation_manager=None,  # allocation_manager_instance,#
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=None,  # permission_controller_instance,#
            reward_coordinator=None,  # rewards_coordinator_instance,#
            registry_coordinator=registry_coordinator_instance,
            strategy_manager=strategy_manager_instance,  #
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
        service_manager_addr = registry_coordinator_instance.functions.serviceManager().call()
        service_manager_instance = eth_http_client.eth.contract(
            address=service_manager_addr,
            abi=ABIs.STRATEGY_MANAGER_ABI,
        )
        stake_registry_addr = registry_coordinator_instance.functions.stakeRegistry().call()
        stake_registry_instance = eth_http_client.eth.contract(
            address=stake_registry_addr,
            abi=ABIs.STAKE_REGISTRY_ABI,
        )
        avs_reader_instance = avs_reader.AvsRegistryReader(
            registry_coordinator=registry_coordinator_instance,
            registry_coordinator_addr=self.registry_coordinator_addr,
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
            service_manager_addr=service_manager_addr,
            stake_registry=stake_registry_instance,
            bls_apk_registry=bls_apk_registry_instance,
            el_reader=el_chain_reader,
            logger=self.logger,
            eth_http_client=eth_http_client,
            pk_wallet=pk_wallet,
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
        metrics: Optional[Any],
    ):
        self.avs_registry_reader = avs_registry_reader
        self.avs_registry_writer = avs_registry_writer
        self.el_reader = el_reader
        self.el_writer = el_writer
        self.eth_http_client = eth_http_client
        self.wallet = wallet
        self.metrics = metrics


def build_all(
    config: BuildAllConfig,
    config_ecdsa_private_key: str,
    config_reward_coordinator: Address,
) -> Clients:
    eth_http_client = Web3(Web3.HTTPProvider(config.eth_http_url))
    pk_wallet: LocalAccount = (
        Account.from_key(config_ecdsa_private_key) if config_ecdsa_private_key else None
    )

    el_reader, el_writer = config.build_el_clients(
        ecdsa_private_key=config_ecdsa_private_key,
        reward_coordinator=config_reward_coordinator,
    )

    avs_reader, avs_writer = config.build_avs_registry_clients(
        ecdsa_private_key=config_ecdsa_private_key,
        el_chain_reader=el_reader,
    )

    return Clients(
        avs_registry_reader=avs_reader,
        avs_registry_writer=avs_writer,
        el_reader=el_reader,
        el_writer=el_writer,
        eth_http_client=eth_http_client,
        wallet=pk_wallet,
        metrics=None,
    )
