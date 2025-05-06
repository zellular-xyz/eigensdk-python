#!/bin/bash
# Script to run chainio tests against Anvil

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}EigenSDK ChainIO Tests Runner${NC}"
echo "============================="

# Check if Anvil is installed
if ! command -v anvil &> /dev/null
then
    echo -e "${RED}Error: anvil could not be found${NC}"
    echo "Please install Foundry (https://book.getfoundry.sh/getting-started/installation)"
    exit 1
fi

# Check if pytest is installed
if ! command -v pytest &> /dev/null
then
    echo -e "${RED}Error: pytest could not be found${NC}"
    echo "Please install pytest: pip install pytest"
    exit 1
fi

# Function to check if Anvil is running
check_anvil() {
    curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' http://localhost:8545 > /dev/null
    return $?
}

# Parse arguments
RUN_UNIT_TESTS=true
RUN_ANVIL_TESTS=false
START_ANVIL=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --all) RUN_UNIT_TESTS=true; RUN_ANVIL_TESTS=true ;;
        --unit) RUN_UNIT_TESTS=true; RUN_ANVIL_TESTS=false ;;
        --anvil) RUN_UNIT_TESTS=false; RUN_ANVIL_TESTS=true ;;
        --start-anvil) START_ANVIL=true ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# If starting Anvil is requested, do it in the background
ANVIL_PID=""
if [ "$START_ANVIL" = true ]; then
    echo -e "${YELLOW}Starting Anvil in the background...${NC}"
    anvil > anvil.log 2>&1 &
    ANVIL_PID=$!
    echo "Anvil started with PID: $ANVIL_PID"
    echo "Waiting for Anvil to initialize..."
    sleep 3
fi

# Check if Anvil is running if needed for tests
if [ "$RUN_ANVIL_TESTS" = true ]; then
    echo "Checking if Anvil is running..."
    if check_anvil; then
        echo -e "${GREEN}Anvil is running.${NC}"
    else
        echo -e "${RED}Anvil is not running. Start it with 'anvil' in another terminal or use the --start-anvil flag.${NC}"
        exit 1
    fi
fi

# Create the results directory if it doesn't exist
mkdir -p test_results

# Run unit tests
if [ "$RUN_UNIT_TESTS" = true ]; then
    echo -e "\n${YELLOW}Running Unit Tests${NC}"
    echo "====================="
    
    # Run tests for utils
    echo -e "\n${YELLOW}Testing ChainIO Utils${NC}"
    pytest -xvs tests/ChainIO/Anvil/test_utils.py | tee test_results/utils.log
    
    # Run tests for AVSRegistry Reader
    echo -e "\n${YELLOW}Testing AVSRegistry Reader${NC}"
    pytest -xvs tests/ChainIO/Anvil/AVSRegistry/Reader/test_avs_reader.py | tee test_results/avs_reader.log
    
    # Run tests for AVSRegistry Writer
    echo -e "\n${YELLOW}Testing AVSRegistry Writer${NC}"
    pytest -xvs tests/ChainIO/Anvil/AVSRegistry/Writer/test_avs_writer.py | tee test_results/avs_writer.log
    
    # Run tests for EigenLayer Reader
    echo -e "\n${YELLOW}Testing EigenLayer Reader${NC}"
    pytest -xvs tests/ChainIO/Anvil/EigenLayer/Reader/test_el_reader.py | tee test_results/el_reader.log
    
    # Run tests for EigenLayer Writer
    echo -e "\n${YELLOW}Testing EigenLayer Writer${NC}"
    pytest -xvs tests/ChainIO/Anvil/EigenLayer/Writer/test_el_writer.py | tee test_results/el_writer.log
fi

# Run Anvil integration tests
if [ "$RUN_ANVIL_TESTS" = true ]; then
    echo -e "\n${YELLOW}Running Anvil Integration Tests${NC}"
    echo "============================"
    
    # First test connection to Anvil
    echo -e "\n${YELLOW}Testing Connection to Anvil${NC}"
    ANVIL_RUNNING=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py::TestWithAnvil::test_eigenlayer_connection | tee test_results/anvil_connection.log
    
    # Check if contracts are deployed
    echo -e "\n${YELLOW}Checking if Contracts are Deployed${NC}"
    echo "Note: This may fail if you haven't deployed contracts yet or if the addresses are incorrect."
    echo "If it fails, run the deploy_contracts.py script to deploy contracts and update addresses."
    ANVIL_RUNNING=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py::TestWithAnvil::test_contract_deployed | tee test_results/contract_deployed.log
    
    # Only run contract tests if explicitly set
    if [ -n "$CONTRACTS_DEPLOYED" ]; then
        echo -e "\n${YELLOW}Running Tests with Deployed Contracts${NC}"
        ANVIL_RUNNING=1 CONTRACTS_DEPLOYED=1 pytest -xvs tests/ChainIO/Anvil/test_with_anvil.py | tee test_results/with_contracts.log
    else
        echo -e "\n${YELLOW}Skipping tests that require deployed contracts${NC}"
        echo "Set CONTRACTS_DEPLOYED=1 to run these tests after deploying contracts."
    fi
fi

# Kill Anvil if we started it
if [ -n "$ANVIL_PID" ]; then
    echo -e "\n${YELLOW}Stopping Anvil (PID: $ANVIL_PID)${NC}"
    kill $ANVIL_PID
    echo "Anvil stopped."
fi

echo -e "\n${GREEN}Tests completed.${NC}"
echo "Test logs are available in the test_results directory."
echo "=================================================="

exit 0 