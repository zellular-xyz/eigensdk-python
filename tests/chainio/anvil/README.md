# ChainIO Tests with Anvil

This directory contains tests for the `eigensdk.chainio` module using Anvil as a local Ethereum node for testing.

## Test Structure

- `AVSRegistry/` - Tests for the AVSRegistry reader and writer functionality
- `EigenLayer/` - Tests for the EigenLayer reader and writer functionality
- `test_utils.py` - Tests for utility functions in `eigensdk.chainio.utils`
- `test_with_anvil.py` - Tests that run against a local Anvil instance with deployed contracts

## Required Setup

1. **Anvil**: You need to have Anvil (part of Foundry) installed. If you don't have it, you can install it:
   ```
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Deployed Contracts**: You need to have the EigenLayer contracts deployed to Anvil. You can:
   - Deploy them manually using scripts in the eigenlayer-contracts directory
   - Or use a script to deploy them to Anvil

## Running Tests

### 1. Start Anvil

Start a local Anvil instance:

```
anvil
```

### 2. Deploy Contracts (if needed)

If you haven't deployed the contracts, you need to deploy them to Anvil first. You can use the deployment scripts from the eigenlayer-contracts repository or deploy them using a script.

### 3. Update Contract Addresses

Update the contract addresses in `test_with_anvil.py` with the addresses of your deployed contracts.

### 4. Run the Tests

#### Running Mock Tests

These tests use mocks and don't require a running Anvil instance:

```
pytest -xvs tests/ChainIO/Anvil/test_utils.py
pytest -xvs tests/ChainIO/Anvil/AVSRegistry/Reader/test_avs_reader.py
pytest -xvs tests/ChainIO/Anvil/AVSRegistry/Writer/test_avs_writer.py
pytest -xvs tests/ChainIO/Anvil/EigenLayer/Reader/test_el_reader.py
pytest -xvs tests/ChainIO/Anvil/EigenLayer/Writer/test_el_writer.py
```

#### Running Tests Against Anvil

These tests require a running Anvil instance:

```
# Just check if Anvil is running
ANVIL_RUNNING=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py::TestWithAnvil::test_eigenlayer_connection

# Check if contracts are deployed 
ANVIL_RUNNING=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py::TestWithAnvil::test_contract_deployed

# Run tests that interact with deployed contracts
ANVIL_RUNNING=1 CONTRACTS_DEPLOYED=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py
```

### 5. Adding New Tests

When adding new tests:

1. Follow the existing pattern for test organization
2. Use pytest fixtures to set up test dependencies
3. Use mocking when appropriate to avoid requiring actual blockchain interaction
4. For tests that do require blockchain interaction, make them conditional based on environment variables

## Tips for Testing with Anvil

1. **Resetting State**: You can reset Anvil's state by restarting it
2. **Fixed Private Keys**: Anvil provides fixed accounts with known private keys for testing
3. **Block Time**: By default, Anvil mines blocks instantly, but you can configure it to use a block time
4. **Forking Mainnet**: You can fork mainnet to test against production contracts
5. **Debugging**: Use `print()` statements or the pytest `-v` flag for more verbose output 