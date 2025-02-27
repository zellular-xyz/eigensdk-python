# from web3 import Web3

# class TxManager:
#     def __init__(self, w3: Web3, sender_address: str, private_key: str):
#         self.w3 = w3
#         self.sender_address = sender_address
#         self.private_key = private_key

#         if not Web3.is_address(self.sender_address):
#             raise ValueError(f"Invalid sender address: {self.sender_address}")

#     def get_no_send_tx_opts(self):
#         nonce = self.w3.eth.get_transaction_count(self.sender_address)
#         base_fee = self.w3.eth.gas_price  # Fetch base fee for EIP-1559 networks

#         tx_opts = {
#             'from': self.sender_address,
#             'nonce': nonce,
#             'gas': 2000000,
#             'maxFeePerGas': base_fee + Web3.to_wei(2, "gwei"),
#             'maxPriorityFeePerGas': Web3.to_wei(2, "gwei"),
#         }
#         return tx_opts

#     def Send(self, tx, wait_for_receipt=True):
#         signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.private_key)
#         tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

#         if wait_for_receipt:
#             receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
#             return receipt
#         return tx_hash


import time
import logging
from web3 import Web3
from web3.exceptions import TransactionNotFound
from eth_account import Account

# Default values similar to Go implementation
FALLBACK_GAS_TIP_CAP = Web3.to_wei(5, "gwei")  # 5 gwei
FALLBACK_GAS_LIMIT_MULTIPLIER = 1.2


class TxManager:
    def __init__(
        self,
        w3: Web3,
        sender_address: str,
        private_key: str,
        gas_limit_multiplier=FALLBACK_GAS_LIMIT_MULTIPLIER,
    ):
        self.w3 = w3
        self.sender_address = Web3.to_checksum_address(sender_address)
        self.private_key = private_key
        self.gas_limit_multiplier = gas_limit_multiplier

        if not Web3.is_address(self.sender_address):
            raise ValueError(f"Invalid sender address: {self.sender_address}")

        self.account = Account.from_key(private_key)
        self.logger = logging.getLogger("TxManager")

    def get_no_send_tx_opts(self):
        """Generate transaction options without sending the transaction."""
        nonce = self.w3.eth.get_transaction_count(self.sender_address)
        base_fee = self.w3.eth.gas_price  # Fetch base fee for EIP-1559 networks

        tx_opts = {
            "from": self.sender_address,
            "nonce": nonce,
            "gas": 2000000,  # Placeholder; real value should be estimated
            "maxFeePerGas": base_fee + Web3.to_wei(2, "gwei"),
            "maxPriorityFeePerGas": Web3.to_wei(2, "gwei"),
        }
        return tx_opts

    def send(self, tx, wait_for_receipt=True):
        """Send transaction with gas estimation and nonce handling."""
        tx = self.estimate_gas_and_nonce(tx)
        signed_tx = self.w3.eth.account.sign_transaction(
            tx, private_key=self.private_key
        )
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

        self.logger.info(f"Transaction sent: {tx_hash.hex()}")

        if wait_for_receipt:
            return self.wait_for_receipt(tx_hash.hex())
        return tx_hash.hex()

    def send_with_retry(self, tx, max_retries=3, delay=2):
        """Retry transaction sending with exponential backoff (only for network-related failures)."""
        for attempt in range(max_retries):
            try:
                return self.send(tx, wait_for_receipt=True)
            except TransactionNotFound:
                self.logger.warning(
                    f"Transaction {tx} not found. Retrying ({attempt+1}/{max_retries})..."
                )
            except Exception as e:
                # If it's a contract logic error, don't retry
                if "revert" in str(e).lower():
                    raise RuntimeError(f"Transaction reverted: {e}")
                self.logger.warning(f"Attempt {attempt+1} failed: {e}")
            time.sleep(delay * (2**attempt))  # Exponential backoff
        raise RuntimeError("Transaction failed after multiple retries")

    def wait_for_receipt(self, tx_hash, timeout=120, poll_interval=2):
        """Poll for transaction receipt."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash)
                if receipt:
                    self.logger.info(
                        f"✅ Transaction confirmed! Hash: {tx_hash}, Block: {receipt['blockNumber']}"
                    )
                    return receipt
            except TransactionNotFound:
                self.logger.info(
                    f"⏳ Waiting for transaction {tx_hash} to be confirmed..."
                )
            time.sleep(poll_interval)
        raise TimeoutError(
            f"Transaction {tx_hash} not confirmed within {timeout} seconds"
        )

    def estimate_gas_and_nonce(self, tx):
        """Estimate gas and nonce, adding buffer to the gas limit."""
        nonce = self.w3.eth.get_transaction_count(self.sender_address)
        base_fee = self.w3.eth.gas_price  # EIP-1559 base fee

        try:
            estimated_gas = self.w3.eth.estimate_gas(tx)
        except Exception as e:
            self.logger.warning(
                f"Gas estimation failed, using fallback (500,000 gas): {e}"
            )
            estimated_gas = 500000  # More reasonable fallback gas limit

        gas_fee_cap = base_fee * 2 + FALLBACK_GAS_TIP_CAP  # Similar logic to Go
        gas_limit = int(estimated_gas * self.gas_limit_multiplier)

        tx.update(
            {
                "nonce": nonce,
                "gas": gas_limit,
                "maxFeePerGas": gas_fee_cap,
                "maxPriorityFeePerGas": FALLBACK_GAS_TIP_CAP,
            }
        )

        return tx
