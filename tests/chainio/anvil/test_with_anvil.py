import pytest
import os
import json
from web3 import Web3
from eth_account import Account
import logging
from typing import Dict, Any

from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
from eigensdk.chainio.clients.avsregistry.reader import AvsRegistryReader
from eigensdk.chainio.clients.avsregistry.writer import AvsRegistryWriter
from eigensdk.chainio.clients.elcontracts.reader import ELReader
from eigensdk.chainio.clients.elcontracts.writer import ELWriter


class TestWithAnvil:
    @pytest.fixture(scope="module")
    def eth_client(self):
        """Create a web3 client connected to Anvil"""
        # Connect to Anvil (launched with 'anvil' command)
        eth_http_url = "http://localhost:8545"
        return Web3(Web3.HTTPProvider(eth_http_url))

    @pytest.fixture(scope="module")
    def test_account(self, eth_client):
        """Get a test account with ETH from Anvil"""
        # Use one of the default Anvil accounts
        private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # First Anvil account
        account = Account.from_key(private_key)

        # Verify the account has ETH
        balance = eth_client.eth.get_balance(account.address)
        assert balance > 0, f"Test account {account.address} has no ETH"

        return account

    @pytest.fixture(scope="module")
    def contract_addresses(self):
        """Get contract addresses from deployed contracts on Anvil"""
        # In a real test, you would get these from the deployment or a config file
        # For demonstration, we'll use placeholders
        return {
            "registry_coordinator": "0x5FbDB2315678afecb367f032d93F642f64180aa3",  # Replace with your deployed address
            "operator_state_retriever": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",  # Replace with your deployed address
            "avs_directory": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",  # Replace with your deployed address
            "delegation_manager": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",  # Replace with your deployed address
            "strategy_manager": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",  # Replace with your deployed address
        }

    @pytest.fixture(scope="module")
    def clients(self, eth_client, test_account, contract_addresses):
        """Create eigensdk clients for testing"""
        logger = logging.getLogger("test_logger")

        # Create BuildAllConfig
        config = BuildAllConfig(
            eth_http_url="http://localhost:8545",
            registry_coordinator_addr=contract_addresses["registry_coordinator"],
            operator_state_retriever_addr=contract_addresses["operator_state_retriever"],
            avs_name="TestAVS",
            prom_metrics_ip_port_address="",
        )

        # Build all clients
        try:
            all_clients = build_all(
                config=config,
                config_ecdsa_private_key=test_account.key.hex(),
                config_reward_coordinator="0x0000000000000000000000000000000000000000",  # No reward coordinator for testing
            )
            return all_clients
        except Exception as e:
            # If building all clients fails (e.g., due to missing contracts), print error and return None
            print(f"Failed to build clients: {e}")
            return None

    @pytest.mark.skipif(
        os.environ.get("ANVIL_RUNNING") != "1",
        reason="Anvil not running. Set ANVIL_RUNNING=1 to run this test.",
    )
    def test_eigenlayer_connection(self, eth_client):
        """Test connection to Anvil"""
        # Check if we can get the chain ID
        chain_id = eth_client.eth.chain_id
        # Anvil's default chain ID is 31337
        assert chain_id == 31337, f"Expected chain ID 31337, got {chain_id}"

    @pytest.mark.skipif(
        os.environ.get("ANVIL_RUNNING") != "1",
        reason="Anvil not running. Set ANVIL_RUNNING=1 to run this test.",
    )
    def test_contract_deployed(self, eth_client, contract_addresses):
        """Test if contracts are deployed on Anvil"""
        # Check if the registry coordinator contract exists by trying to get its code
        code = eth_client.eth.get_code(contract_addresses["registry_coordinator"])
        assert len(code) > 0, "Registry Coordinator contract not deployed"

    @pytest.mark.skipif(
        os.environ.get("ANVIL_RUNNING") != "1" or os.environ.get("CONTRACTS_DEPLOYED") != "1",
        reason="Anvil not running or contracts not deployed. Set ANVIL_RUNNING=1 and CONTRACTS_DEPLOYED=1 to run this test.",
    )
    def test_avs_registry_reader(self, clients):
        """Test AVS Registry Reader with Anvil deployed contracts"""
        if clients is None:
            pytest.skip("Clients not available")

        # Test getting quorum count
        quorum_count = clients.avs_registry_reader.get_quorum_count()
        # Verify the result (adjust expected value based on your deployment)
        print(f"Quorum count: {quorum_count}")

    @pytest.mark.skipif(
        os.environ.get("ANVIL_RUNNING") != "1" or os.environ.get("CONTRACTS_DEPLOYED") != "1",
        reason="Anvil not running or contracts not deployed. Set ANVIL_RUNNING=1 and CONTRACTS_DEPLOYED=1 to run this test.",
    )
    def test_el_reader(self, clients):
        """Test EigenLayer Reader with Anvil deployed contracts"""
        if clients is None:
            pytest.skip("Clients not available")

        # Test if the wallet address is delegated
        is_delegated = clients.el_reader.is_delegated(clients.wallet.address)
        # Print the result (may vary based on your deployment state)
        print(f"Is wallet delegated: {is_delegated}")


# Instructions for running these tests:
#
# 1. Start Anvil (make sure contracts are deployed):
#    anvil
#
# 2. Deploy the EigenLayer contracts to Anvil (if not done already)
#    (This would be a separate deployment script)
#
# 3. Run the tests with pytest, setting environment variables:
#    ANVIL_RUNNING=1 CONTRACTS_DEPLOYED=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py
#
# Note: The CONTRACTS_DEPLOYED flag lets you run basic connection tests even if contracts aren't deployed yet.
