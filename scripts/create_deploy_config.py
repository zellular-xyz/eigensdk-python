#!/usr/bin/env python3

import json
import os
from pathlib import Path


def create_deployment_config():
    """Create the deployment configuration file if it doesn't exist."""
    config_dir = Path("/app/eigenlayer-contracts/local")
    config_file = config_dir / "deploy_from_scratch.slashing.anvil.config.json"

    # Create directory if it doesn't exist
    config_dir.mkdir(exist_ok=True, parents=True)

    # Check if file already exists
    if config_file.exists():
        print(f"✅ Config file already exists at {config_file}")
        return

    # Default configuration for Anvil deployment
    config = {
        "chain": {"name": "anvil", "chainId": 31337},
        "deploymentParams": {
            "baseDeploymentParams": {
                "blockConfirmations": 0,
                "waitForConfirmations": False,
                "initialPauseStatus": False,
            }
        },
        "operatorSetupParams": {
            "numOperators": 10,
            "operatorInitialEthAmount": "10000000000000000000",
            "operatorInitialEigAmount": "10000000000000000000",
            "operatorInitialEigDelegationAmount": "1000000000000000000",
        },
        "avsValidatorServiceParams": {
            "numBLSKeysPerOperator": 1,
            "numOperators": 3,
            "validatorWeightBasisPoints": 1000,
        },
    }

    # Write config to file
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)

    print(f"✅ Created config file at {config_file}")


if __name__ == "__main__":
    create_deployment_config()
