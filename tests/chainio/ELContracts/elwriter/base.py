import logging
from web3 import Web3
from eth_typing import Address
from eigensdk.chainio.clients.elcontracts import writer
from eigensdk.chainio.clients.elcontracts import txmanager
from eigensdk.contracts.ABIs import LoadABI

# Setup Web3 Connection to Anvil
ANVIL_RPC_URL = "http://127.0.0.1:8545"  # Adjust if using a different port
w3 = Web3(Web3.HTTPProvider(ANVIL_RPC_URL))

# Contract Addresses
CONTRACT_ADDRESSES = {
    "allocation_manager": "0x2279B7A0a67DB372996a5FaB50D91eAA73d2eBe6",
    "avs_directory": "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707",
    "delegation_manager": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
    "permission_control": "0x8A791620dd6260079BF849Dc5567aDC3F2FdC318",
    "strategy_manager": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
    "rewards_coordinator": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
    "ierc20": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
    "istrategy": "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
}




# Initialize contract instances
allocation_manager = w3.eth.contract(
    address=CONTRACT_ADDRESSES["allocation_manager"], abi=LoadABI.ALLOCATION_MANAGER_ABI()
)
avs_directory = w3.eth.contract(
    address=CONTRACT_ADDRESSES["avs_directory"], abi=LoadABI.AVS_DIRECTORY_ABI()
)
delegation_manager = w3.eth.contract(
    address=CONTRACT_ADDRESSES["delegation_manager"], abi=LoadABI.DELEGATION_MANAGER_ABI()
)
permission_control = w3.eth.contract(
    address=CONTRACT_ADDRESSES["permission_control"], abi=LoadABI.PERMISSION_CONTROL_ABI()
)
strategy_manager = w3.eth.contract(
    address=CONTRACT_ADDRESSES["strategy_manager"], abi=LoadABI.STRATEGY_MANAGER_ABI()
)
rewards_coordinator = w3.eth.contract(
    address=CONTRACT_ADDRESSES["rewards_coordinator"], abi=LoadABI.REWARDS_COORDINATOR_ABI()
)


# Logger setup
logger = logging.getLogger("ELReaderTest")
logger.setLevel(logging.INFO)

# Initialize ELReader instance
el_writer = writer.ELWriter(
    allocation_manager=allocation_manager,
    avs_directory=avs_directory,
    delegation_manager=delegation_manager,
    permissioncontrol=permission_control,
    reward_cordinator=rewards_coordinator,
    strategy_manager=strategy_manager,
    logger=logger,
    eth_http_client=w3,
    strategy_abi=LoadABI.ISTRATEGY_ABI(),
    erc20_abi=LoadABI.IERC20_ABI(),
)

# Example sender address and private key (replace with actual)
SENDER_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

tx_mgr = txmanager.TxManager(w3, SENDER_ADDRESS, PRIVATE_KEY)