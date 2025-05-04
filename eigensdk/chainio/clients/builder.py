import logging
from eth_typing import Address
from web3 import Web3
from typing import Any, Optional
from eigensdk.chainio.clients.avsregistry import reader as avs_reader
from eigensdk.chainio.clients.avsregistry import writer as avs_writer
from eigensdk.chainio.clients.elcontracts import reader as el_reader
from eigensdk.chainio.clients.elcontracts import writer as el_writer
from eigensdk.chainio.txmgr import txmanager
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

        self.eth_client = Web3(Web3.HTTPProvider(eth_http_url))
        self.registry_coordinator_addr: Address = registry_coordinator_addr
        self.operator_state_retriever_addr: Address = operator_state_retriever_addr
        self.avs_name: str = avs_name
        self.prom_metrics_ip_port_address: str = prom_metrics_ip_port_address
        self.logger: logging.Logger = logging.getLogger(__name__)

    def build_el_reader_clients(
        self,
        allocation_manager: Address,
        avs_directory: Address,
        delegation_manager: Address,
        permission_controller: Address,
        reward_coordinator: Address,
        strategy_manager: Address,
    ) -> el_reader.ELReader:

        allocation_manager_instance = self.eth_client.eth.contract(
            address=allocation_manager, abi=ABIs.ALLOCATION_MANAGER_ABI
        )
        avs_directory_instance = self.eth_client.eth.contract(
            address=avs_directory, abi=ABIs.AVS_DIRECTORY_ABI
        )
        delegation_manager_instance = self.eth_client.eth.contract(
            address=delegation_manager, abi=ABIs.DELEGATION_MANAGER_ABI
        )
        permission_controller_instance = self.eth_client.eth.contract(
            address=permission_controller, abi=ABIs.PERMISSION_CONTROLLER_ABI
        )
        strategy_manager_instance = self.eth_client.eth.contract(
            address=strategy_manager, abi=ABIs.STRATEGY_MANAGER_ABI
        )
        rewards_coordinator_instance = self.eth_client.eth.contract(
            address=reward_coordinator, abi=ABIs.REWARDS_COORDINATOR_ABI
        )

        el_reader_instance = el_reader.ELReader(
            allocation_manager=allocation_manager_instance,
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=permission_controller_instance,
            reward_coordinator=rewards_coordinator_instance,
            strategy_manager=strategy_manager_instance,
            logger=self.logger,
            eth_client=self.eth_client,
            strategy_abi=ABIs.I_STRATEGY_ABI,
            erc20_abi=ABIs.IERC20_ABI,
        )

        return el_reader_instance

    def build_el_writer_clients(
        self,
        operator_ecdsa_private_key: str,
        allocation_manager: Address,
        avs_directory: Address,
        delegation_manager: Address,
        permission_controller: Address,
        reward_coordinator: Address,
        registry_coordinator: Address,
        strategy_manager: Address,
        strategy_manager_addr: Address,
        el_chain_reader: el_reader.ELReader,
    ) -> el_writer.ELWriter:

        pk_wallet = Account.from_key(operator_ecdsa_private_key)

        allocation_manager_instance = self.eth_client.eth.contract(
            address=allocation_manager, abi=ABIs.ALLOCATION_MANAGER_ABI
        )
        avs_directory_instance = self.eth_client.eth.contract(
            address=avs_directory, abi=ABIs.AVS_DIRECTORY_ABI
        )
        delegation_manager_instance = self.eth_client.eth.contract(
            address=delegation_manager, abi=ABIs.DELEGATION_MANAGER_ABI
        )
        permission_controller_instance = self.eth_client.eth.contract(
            address=permission_controller, abi=ABIs.PERMISSION_CONTROLLER_ABI
        )
        strategy_manager_instance = self.eth_client.eth.contract(
            address=strategy_manager, abi=ABIs.STRATEGY_MANAGER_ABI
        )
        rewards_coordinator_instance = self.eth_client.eth.contract(
            address=reward_coordinator, abi=ABIs.REWARDS_COORDINATOR_ABI
        )

        registry_coordinator_instance = self.eth_client.eth.contract(
            address=registry_coordinator, abi=ABIs.REGISTRY_COORDINATOR_ABI
        )

        el_writer_instance = el_writer.ELWriter(
            allocation_manager=allocation_manager_instance,
            avs_directory=avs_directory_instance,
            delegation_manager=delegation_manager_instance,
            permission_controller=permission_controller_instance,
            reward_coordinator=rewards_coordinator_instance,
            registry_coordinator=registry_coordinator_instance,
            strategy_manager=strategy_manager_instance,
            strategy_manager_addr=strategy_manager_addr,
            el_chain_reader=el_chain_reader,
            logger=self.logger,
            tx_mgr=txmanager.TxManager(
                self.eth_client, pk_wallet.address, operator_ecdsa_private_key
            ),
            pk_wallet=pk_wallet,
            eth_client=self.eth_client,
            strategy_abi=ABIs.I_STRATEGY_ABI,
            erc20_abi=ABIs.IERC20_ABI,
        )

        return el_writer_instance

    def build_avs_registry_reader_clients(
        self,
        operator_ecdsa_private_key: str,
        registry_coordinator: Address,
        registry_coordinator_addr: Address,
        bls_apk_registry: Address,
        bls_apk_registry_addr: Address,
        operator_state_retriever: Address,
        service_manager: Address,
        stake_registry: Address,
    ) -> avs_reader.AvsRegistryReader:

        pk_wallet = Account.from_key(operator_ecdsa_private_key)

        registry_coordinator_instance = self.eth_client.eth.contract(
            address=registry_coordinator, abi=ABIs.REGISTRY_COORDINATOR_ABI
        )
        operator_state_retriever_instance = self.eth_client.eth.contract(
            address=operator_state_retriever, abi=ABIs.OPERATOR_STATE_RETRIEVER_ABI
        )
        bls_apk_registry_instance = self.eth_client.eth.contract(
            address=bls_apk_registry, abi=ABIs.BLS_APK_REGISTRY_ABI
        )
        service_manager_instance = self.eth_client.eth.contract(
            address=service_manager, abi=ABIs.STRATEGY_MANAGER_ABI
        )
        stake_registry_instance = self.eth_client.eth.contract(
            address=stake_registry, abi=ABIs.STAKE_REGISTRY_ABI
        )

        avs_reader_instance = avs_reader.AvsRegistryReader(
            registry_coordinator=registry_coordinator_instance,
            registry_coordinator_addr=registry_coordinator_addr,
            bls_apk_registry=bls_apk_registry_instance,
            bls_apk_registry_addr=bls_apk_registry_addr,
            operator_state_retriever=operator_state_retriever_instance,
            service_manager=service_manager_instance,
            stake_registry=stake_registry_instance,
            logger=self.logger,
            eth_client=self.eth_client,
            tx_mgr=txmanager.TxManager(
                self.eth_client, pk_wallet.address, operator_ecdsa_private_key
            ),
            pk_wallet=pk_wallet
        )

        return avs_reader_instance

    def build_avs_registry_writer_clients(
        self,
        operator_ecdsa_private_key: str,
        registry_coordinator: Address,
        operator_state_retriever: Address,
        service_manager: Address,
        service_manager_addr: Address,
        stake_registry: Address,
        bls_apk_registry: Address,
        el_chain_reader: el_reader.ELReader,
    ) -> avs_writer.AvsRegistryWriter:

        pk_wallet = Account.from_key(operator_ecdsa_private_key)

        registry_coordinator_instance = self.eth_client.eth.contract(
            address=registry_coordinator, abi=ABIs.REGISTRY_COORDINATOR_ABI
        )
        operator_state_retriever_instance = self.eth_client.eth.contract(
            address=operator_state_retriever, abi=ABIs.OPERATOR_STATE_RETRIEVER_ABI
        )
        bls_apk_registry_instance = self.eth_client.eth.contract(
            address=bls_apk_registry, abi=ABIs.BLS_APK_REGISTRY_ABI
        )
        service_manager_instance = self.eth_client.eth.contract(
            address=service_manager, abi=ABIs.STRATEGY_MANAGER_ABI
        )
        stake_registry_instance = self.eth_client.eth.contract(
            address=stake_registry, abi=ABIs.STAKE_REGISTRY_ABI
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
            eth_client=self.eth_client,
            tx_mgr=txmanager.TxManager(
                self.eth_client, pk_wallet.address, operator_ecdsa_private_key
            ),
            pk_wallet=pk_wallet,
        )

        return avs_writer_instance


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
    config_operator_ecdsa_private_key: str,
    config_allocation_manager: Address,
    config_avs_directory: Address,
    config_delegation_manager: Address,
    config_permission_controller: Address,
    config_reward_coordinator: Address,
    config_registry_coordinator_addr: Address,
    config_strategy_manager: Address,
    config_registry_coordinator: Address,
    config_strategy_manager_addr: Address,
    config_service_manager: Address,
    config_service_manager_addr: Address,
    config_stake_registry: Address,
    config_bls_apk_registry: Address,
    config_bls_apk_registry_addr: Address,
    config_operator_state_retriever: Address,
) -> Clients:
    eth_http_client = Web3(Web3.HTTPProvider(config.eth_client))
    pk_wallet: LocalAccount = (
        Account.from_key(config_operator_ecdsa_private_key)
        if config_operator_ecdsa_private_key
        else None
    )

    # Build EL reader client
    el_reader = config.build_el_reader_clients(
        allocation_manager=config_allocation_manager,
        avs_directory=config_avs_directory,
        delegation_manager=config_delegation_manager,
        permission_controller=config_permission_controller,
        reward_coordinator=config_reward_coordinator,
        strategy_manager=config_strategy_manager,
    )

    # Build EL writer client
    el_writer = config.build_el_writer_clients(
        operator_ecdsa_private_key=config_operator_ecdsa_private_key,
        allocation_manager=config_allocation_manager,
        avs_directory=config_avs_directory,
        delegation_manager=config_delegation_manager,
        permission_controller=config_permission_controller,
        reward_coordinator=config_reward_coordinator,
        registry_coordinator=config_registry_coordinator,
        strategy_manager=config_strategy_manager,
        strategy_manager_addr=config_strategy_manager_addr,
        el_chain_reader=el_reader,
    )

    # Build AVS registry reader client
    avs_registry_reader = config.build_avs_registry_reader_clients(
        operator_ecdsa_private_key=config_operator_ecdsa_private_key,
        registry_coordinator=config_registry_coordinator,
        registry_coordinator_addr=config_registry_coordinator_addr,
        bls_apk_registry=config_bls_apk_registry,
        bls_apk_registry_addr=config_bls_apk_registry_addr,
        operator_state_retriever=config_operator_state_retriever,
        service_manager=config_service_manager,
        stake_registry=config_stake_registry,
    )

    # Build AVS registry writer client
    avs_registry_writer = config.build_avs_registry_writer_clients(
        operator_ecdsa_private_key=config_operator_ecdsa_private_key,
        registry_coordinator=config_registry_coordinator,
        operator_state_retriever=config_operator_state_retriever,
        service_manager=config_service_manager,
        service_manager_addr=config_service_manager_addr,
        stake_registry=config_stake_registry,
        bls_apk_registry=config_bls_apk_registry,
        el_chain_reader=el_reader,
    )

    return Clients(
        avs_registry_reader=avs_registry_reader,
        avs_registry_writer=avs_registry_writer,
        el_reader=el_reader,
        el_writer=el_writer,
        eth_http_client=eth_http_client,
        wallet=pk_wallet,
        metrics=None,
    )
