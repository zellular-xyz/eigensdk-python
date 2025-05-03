from web3 import Web3
from eth_account import Account

ecdsa_private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
pk_wallet = Account.from_key(ecdsa_private_key)
