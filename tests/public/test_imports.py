import pytest
from eigensdk.chainio.clients.builder import BuildAllConfig


def test_build_all_config_import():
    """Test that BuildAllConfig can be imported."""
    # Verify we can import and create a BuildAllConfig instance
    config = BuildAllConfig(
        eth_http_url="http://localhost:8545",
        registry_coordinator_addr="0x1234567890123456789012345678901234567890",
        operator_state_retriever_addr="0x1234567890123456789012345678901234567890",
        avs_name="test",
        prom_metrics_ip_port_address="localhost:9090",
    )

    # Assert the config was created correctly
    assert config.eth_client is not None
    assert config.avs_name == "test"
    assert config.prom_metrics_ip_port_address == "localhost:9090"


def test_basic_assertion():
    """Basic test to verify pytest is working."""
    assert 1 + 1 == 2
