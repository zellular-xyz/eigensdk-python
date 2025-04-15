from eigensdk.chainio.clients.builder import BuildAllConfig
from eigensdk.chainio.txmgr import txmanager
from eigensdk.contracts import ABIs
from eigensdk.crypto import bls


def test_build_all_config_import():
    """Test that BuildAllConfig can be imported and instantiated."""
    config = BuildAllConfig(
        eth_http_url="http://localhost:8545",
        registry_coordinator_addr="0x1234567890123456789012345678901234567890",
        operator_state_retriever_addr="0x1234567890123456789012345678901234567890",
        avs_name="test",
        prom_metrics_ip_port_address="localhost:9090",
    )

    # Testing that the config has the expected attributes based on the actual implementation
    assert config.eth_client is not None
    assert config.avs_name == "test"
    assert config.prom_metrics_ip_port_address == "localhost:9090"
    assert hasattr(config, "logger")


def test_txmanager_import():
    """Test that TxManager can be imported."""
    from web3 import Web3

    # Create a dummy Web3 instance that doesn't connect anywhere
    w3 = Web3()

    # We can instantiate TxManager without errors
    tx_mgr = txmanager.TxManager(
        w3,
        "0x1234567890123456789012345678901234567890",
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    )

    # Testing attributes that actually exist in the class
    assert hasattr(tx_mgr, "w3")
    assert hasattr(tx_mgr, "sender_address")
    assert hasattr(tx_mgr, "private_key")


def test_abi_files_exist():
    """Test that ABI files are included in the package."""
    abi_names = [
        "ALLOCATION_MANAGER_ABI",
        "AVS_DIRECTORY_ABI",
        "BLS_APK_REGISTRY_ABI",
        "DELEGATION_MANAGER_ABI",
        "IERC20_ABI",
        "OPERATOR_STATE_RETRIEVER_ABI",
        "PERMISSION_CONTROLLER_ABI",
        "REGISTRY_COORDINATOR_ABI",
        "REWARDS_COORDINATOR_ABI",
        "SERVICE_MANAGER_BASE_ABI",  # Fixed name based on the actual implementation
        "STAKE_REGISTRY_ABI",
        "STRATEGY_MANAGER_ABI",
    ]

    for abi_name in abi_names:
        assert hasattr(ABIs, abi_name), f"Missing ABI: {abi_name}"
        abi = getattr(ABIs, abi_name)
        assert isinstance(abi, list), f"ABI {abi_name} is not a list"
        assert len(abi) > 0, f"ABI {abi_name} is empty"


def test_bls_module():
    """Test that basic BLS operations work."""
    # Generate a random private key
    private_key = bls.attestation.PrivateKey()
    assert private_key is not None

    # Create a key pair
    key_pair = bls.attestation.BLSKeyPair(private_key)
    assert key_pair is not None

    # Sign a message
    message = b"test message"
    signature = key_pair.sign_message(message)
    assert signature is not None

    # Verify the signature
    pub_key = key_pair.pub_g2
    result = signature.verify(pub_key, message)
    assert result is True
