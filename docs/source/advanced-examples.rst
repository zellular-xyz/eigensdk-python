.. _advanced-examples:

Advanced Examples & Tutorials
=============================

This guide provides comprehensive examples for complex EigenSDK-Python usage patterns, from setting up a complete AVS operator to handling advanced cryptographic operations.

Complete AVS Operator Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~

End-to-End Operator Registration
--------------------------------

This tutorial walks through setting up a complete AVS operator from scratch:

.. code-block:: python

    import os
    import time
    from dotenv import load_dotenv
    from eigensdk.chainio.clients.builder import BuildAllConfig, build_all
    from eigensdk._types import Operator
    from eigensdk.crypto.bls.attestation import KeyPair

    # Load environment variables
    load_dotenv()

    class AVSOperatorManager:
        def __init__(self, config, private_key):
            self.config = config
            self.private_key = private_key
            self.clients = None
            self.bls_key_pair = None
            self.operator_address = None
            
        def initialize(self):
            """Initialize all clients and generate BLS keys."""
            print("🔧 Initializing EigenSDK clients...")
            self.clients = build_all(self.config, self.private_key)
            
            print("🔑 Generating BLS key pair...")
            self.bls_key_pair = KeyPair()
            
            # Get operator address from private key
            from eth_account import Account
            account = Account.from_key(self.private_key)
            self.operator_address = account.address
            
            print(f"✅ Operator address: {self.operator_address}")
            print(f"✅ BLS Public Key: {self.bls_key_pair.get_pub_g1().to_json()}")
            
        def register_with_eigenlayer(self):
            """Register operator with EigenLayer core contracts."""
            print("\n📝 Registering with EigenLayer...")
            
            # Check if already registered
            if self.clients.el_reader.is_operator_registered(self.operator_address):
                print("ℹ️  Operator already registered with EigenLayer")
                return True
            
            # Create operator object
            operator = Operator(
                address=self.operator_address,
                earnings_receiver_address=self.operator_address,  # Use same address for simplicity
                delegation_approver_address="0x0000000000000000000000000000000000000000",  # No approver
                staker_opt_out_window_blocks=50400,  # ~7 days
                allocation_delay=0,
                metadata_url="https://your-domain.com/operator-metadata.json"
            )
            
            # Register operator
            try:
                receipt = self.clients.el_writer.register_as_operator(operator)
                print(f"✅ EigenLayer registration successful!")
                print(f"   Transaction hash: {receipt['transactionHash'].hex()}")
                
                # Wait for confirmation
                self._wait_for_transaction_confirmation(receipt['transactionHash'])
                return True
                
            except Exception as e:
                print(f"❌ EigenLayer registration failed: {e}")
                return False
        
        def register_with_avs(self, quorum_numbers, socket="127.0.0.1:8080"):
            """Register operator with the specific AVS."""
            print(f"\n🏢 Registering with AVS for quorums {quorum_numbers}...")
            
            # Check if already registered
            if self.clients.avs_registry_reader.is_operator_registered(self.operator_address):
                print("ℹ️  Operator already registered with AVS")
                return True
            
            try:
                # Calculate registration signature
                salt = os.urandom(32)
                expiry = int(time.time()) + 3600  # 1 hour from now
                
                # Register with AVS
                receipt = self.clients.avs_registry_writer.register_operator_in_quorum_with_avs_registry_coordinator(
                    operator_ecdsa_private_key=self.private_key,
                    operator_to_avs_registration_sig_salt=salt,
                    operator_to_avs_registration_sig_expiry=expiry,
                    bls_key_pair=self.bls_key_pair,
                    quorum_numbers=quorum_numbers,
                    socket=socket
                )
                
                print(f"✅ AVS registration successful!")
                print(f"   Transaction hash: {receipt.transactionHash.hex()}")
                print(f"   Registered for quorums: {quorum_numbers}")
                
                self._wait_for_transaction_confirmation(receipt.transactionHash)
                return True
                
            except Exception as e:
                print(f"❌ AVS registration failed: {e}")
                return False
        
        def verify_registration(self):
            """Verify operator is properly registered and operational."""
            print("\n🔍 Verifying registration status...")
            
            # Check EigenLayer registration
            el_registered = self.clients.el_reader.is_operator_registered(self.operator_address)
            print(f"   EigenLayer: {'✅' if el_registered else '❌'}")
            
            # Check AVS registration
            avs_registered = self.clients.avs_registry_reader.is_operator_registered(self.operator_address)
            print(f"   AVS Registry: {'✅' if avs_registered else '❌'}")
            
            if avs_registered:
                # Get operator ID
                operator_id = self.clients.avs_registry_reader.get_operator_id(self.operator_address)
                print(f"   Operator ID: {operator_id.hex()}")
                
                # Check quorum membership
                try:
                    quorum_0_operators = self.clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block([0])
                    if quorum_0_operators[0] and self.operator_address in quorum_0_operators[0]:
                        print(f"   Quorum 0: ✅ (Active)")
                    else:
                        print(f"   Quorum 0: ❌ (Not found)")
                except Exception as e:
                    print(f"   Quorum check failed: {e}")
            
            return el_registered and avs_registered
        
        def _wait_for_transaction_confirmation(self, tx_hash, timeout=300):
            """Wait for transaction confirmation with timeout."""
            print(f"⏳ Waiting for transaction confirmation...")
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                try:
                    receipt = self.clients.eth_http_client.eth.get_transaction_receipt(tx_hash)
                    if receipt and receipt.status == 1:
                        print(f"✅ Transaction confirmed in block {receipt.blockNumber}")
                        return True
                    elif receipt and receipt.status == 0:
                        print(f"❌ Transaction failed!")
                        return False
                except:
                    pass  # Transaction not yet mined
                
                time.sleep(10)  # Wait 10 seconds between checks
            
            print(f"⚠️  Transaction confirmation timeout")
            return False

    # Usage example
    def main():
        # Configuration
        config = BuildAllConfig(
            eth_http_url=os.getenv('ETH_RPC_URL'),
            avs_name="my-awesome-avs",
            registry_coordinator_addr=os.getenv('REGISTRY_COORDINATOR_ADDR'),
            operator_state_retriever_addr=os.getenv('OPERATOR_STATE_RETRIEVER_ADDR'),
            rewards_coordinator_addr=os.getenv('REWARDS_COORDINATOR_ADDR'),
            permission_controller_addr="0x0000000000000000000000000000000000000000",
            service_manager_addr=os.getenv('SERVICE_MANAGER_ADDR'),
            allocation_manager_addr=os.getenv('ALLOCATION_MANAGER_ADDR'),
            delegation_manager_addr=os.getenv('DELEGATION_MANAGER_ADDR'),
        )
        
        private_key = os.getenv('PRIVATE_KEY')
        
        # Initialize operator manager
        operator_manager = AVSOperatorManager(config, private_key)
        operator_manager.initialize()
        
        # Complete registration process
        if operator_manager.register_with_eigenlayer():
            if operator_manager.register_with_avs(quorum_numbers=[0, 1]):
                operator_manager.verify_registration()
                print("\n🎉 Operator setup complete!")
            else:
                print("\n❌ AVS registration failed")
        else:
            print("\n❌ EigenLayer registration failed")

    if __name__ == "__main__":
        main()

Multi-Quorum Operations
~~~~~~~~~~~~~~~~~~~~~~

Managing Multiple Quorums
-------------------------

.. code-block:: python

    class MultiQuorumManager:
        def __init__(self, clients):
            self.clients = clients
        
        def get_quorum_overview(self):
            """Get comprehensive overview of all quorums."""
            print("📊 Quorum Overview")
            print("=" * 50)
            
            try:
                quorum_count = self.clients.avs_registry_reader.get_quorum_count()
                print(f"Total Quorums: {quorum_count}")
                
                for quorum_id in range(quorum_count):
                    self._analyze_quorum(quorum_id)
                    
            except Exception as e:
                print(f"Error getting quorum overview: {e}")
        
        def _analyze_quorum(self, quorum_id):
            """Analyze a specific quorum."""
            print(f"\n🏛️  Quorum {quorum_id}")
            print("-" * 20)
            
            try:
                # Get operators and stakes
                operators = self.clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([quorum_id])
                
                if operators and operators[0]:
                    quorum_operators = operators[0]
                    operator_count = len(quorum_operators)
                    total_stake = sum(op.stake for op in quorum_operators)
                    avg_stake = total_stake / operator_count if operator_count > 0 else 0
                    
                    print(f"   Operators: {operator_count}")
                    print(f"   Total Stake: {total_stake / 10**18:.2f} ETH")
                    print(f"   Average Stake: {avg_stake / 10**18:.2f} ETH")
                    
                    # Top 5 operators by stake
                    sorted_operators = sorted(quorum_operators, key=lambda x: x.stake, reverse=True)
                    print("\n   Top 5 Operators:")
                    for i, op in enumerate(sorted_operators[:5]):
                        print(f"   {i+1}. {op.operator} - {op.stake / 10**18:.2f} ETH")
                else:
                    print("   No operators found")
                    
            except Exception as e:
                print(f"   Error analyzing quorum {quorum_id}: {e}")
        
        def update_operator_stakes(self, target_quorums=None):
            """Update stakes for operators in specified quorums."""
            if target_quorums is None:
                target_quorums = [0]  # Default to quorum 0
            
            print(f"🔄 Updating stakes for quorums: {target_quorums}")
            
            try:
                # Get current operators in each quorum
                operators_per_quorum = []
                
                for quorum_id in target_quorums:
                    operator_addresses = self.clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block([quorum_id])
                    if operator_addresses and operator_addresses[0]:
                        operators_per_quorum.append(operator_addresses[0])
                    else:
                        operators_per_quorum.append([])
                
                # Update stakes
                receipt = self.clients.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
                    operators_per_quorum=operators_per_quorum,
                    quorum_numbers=target_quorums
                )
                
                print(f"✅ Stakes updated successfully!")
                print(f"   Transaction hash: {receipt.transactionHash.hex()}")
                
                return True
                
            except Exception as e:
                print(f"❌ Failed to update stakes: {e}")
                return False
        
        def monitor_quorum_changes(self, quorum_id, poll_interval=30):
            """Monitor changes in a specific quorum."""
            print(f"👁️  Monitoring quorum {quorum_id} (polling every {poll_interval}s)")
            print("Press Ctrl+C to stop...")
            
            last_state = None
            
            try:
                while True:
                    current_state = self._get_quorum_state(quorum_id)
                    
                    if last_state is None:
                        print(f"📸 Initial state captured: {len(current_state)} operators")
                    else:
                        self._compare_quorum_states(last_state, current_state, quorum_id)
                    
                    last_state = current_state
                    time.sleep(poll_interval)
                    
            except KeyboardInterrupt:
                print("\n⏹️  Monitoring stopped")
        
        def _get_quorum_state(self, quorum_id):
            """Get current state of a quorum."""
            try:
                operators = self.clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([quorum_id])
                if operators and operators[0]:
                    return {op.operator: op.stake for op in operators[0]}
                return {}
            except:
                return {}
        
        def _compare_quorum_states(self, old_state, new_state, quorum_id):
            """Compare two quorum states and report changes."""
            # New operators
            new_operators = set(new_state.keys()) - set(old_state.keys())
            if new_operators:
                print(f"🆕 New operators in quorum {quorum_id}: {list(new_operators)}")
            
            # Removed operators
            removed_operators = set(old_state.keys()) - set(new_state.keys())
            if removed_operators:
                print(f"❌ Removed operators from quorum {quorum_id}: {list(removed_operators)}")
            
            # Stake changes
            for operator in set(old_state.keys()) & set(new_state.keys()):
                old_stake = old_state[operator]
                new_stake = new_state[operator]
                if old_stake != new_stake:
                    change = (new_stake - old_stake) / 10**18
                    print(f"📈 Stake change for {operator}: {change:+.2f} ETH")

Signature Aggregation Workflows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

BLS Signature Aggregation
-------------------------

.. code-block:: python

    from eigensdk.crypto.bls.attestation import KeyPair, G1Point
    import hashlib

    class SignatureAggregator:
        def __init__(self):
            self.operators = {}  # operator_id -> KeyPair
            self.signatures = {}  # operator_id -> Signature
        
        def add_operator(self, operator_id, key_pair):
            """Add an operator to the aggregation set."""
            self.operators[operator_id] = key_pair
            print(f"✅ Added operator {operator_id}")
        
        def collect_signatures(self, message_bytes, required_operators=None):
            """Collect signatures from operators for a message."""
            if required_operators is None:
                required_operators = list(self.operators.keys())
            
            print(f"📝 Collecting signatures for message: {message_bytes.hex()}")
            
            for operator_id in required_operators:
                if operator_id in self.operators:
                    signature = self.operators[operator_id].sign_message(message_bytes)
                    self.signatures[operator_id] = signature
                    print(f"✅ Signature collected from operator {operator_id}")
                else:
                    print(f"❌ Operator {operator_id} not found")
        
        def aggregate_signatures(self, participating_operators=None):
            """Aggregate signatures from participating operators."""
            if participating_operators is None:
                participating_operators = list(self.signatures.keys())
            
            if len(participating_operators) == 0:
                raise ValueError("No operators to aggregate")
            
            print(f"🔗 Aggregating signatures from {len(participating_operators)} operators")
            
            # Start with first signature
            first_operator = participating_operators[0]
            aggregated_sig = self.signatures[first_operator]
            
            # Add remaining signatures
            for operator_id in participating_operators[1:]:
                if operator_id in self.signatures:
                    aggregated_sig = aggregated_sig.add(self.signatures[operator_id])
            
            print(f"✅ Signatures aggregated successfully")
            return aggregated_sig
        
        def aggregate_public_keys(self, participating_operators=None):
            """Aggregate public keys from participating operators."""
            if participating_operators is None:
                participating_operators = list(self.operators.keys())
            
            if len(participating_operators) == 0:
                raise ValueError("No operators to aggregate")
            
            print(f"🔑 Aggregating public keys from {len(participating_operators)} operators")
            
            # Start with first public key
            first_operator = participating_operators[0]
            aggregated_pubkey = self.operators[first_operator].get_pub_g1()
            
            # Add remaining public keys
            for operator_id in participating_operators[1:]:
                if operator_id in self.operators:
                    operator_pubkey = self.operators[operator_id].get_pub_g1()
                    aggregated_pubkey = aggregated_pubkey.add(operator_pubkey)
            
            print(f"✅ Public keys aggregated successfully")
            return aggregated_pubkey
        
        def verify_aggregated_signature(self, message_bytes, participating_operators=None):
            """Verify the aggregated signature."""
            if participating_operators is None:
                participating_operators = list(self.signatures.keys())
            
            print(f"🔍 Verifying aggregated signature...")
            
            # Aggregate signatures and public keys
            aggregated_sig = self.aggregate_signatures(participating_operators)
            aggregated_pubkey = self.aggregate_public_keys(participating_operators)
            
            # Convert G1 to G2 for verification (simplified - actual implementation may vary)
            # This is a conceptual example - check actual SDK for proper verification
            
            # For demonstration, we'll verify individual signatures
            all_valid = True
            for operator_id in participating_operators:
                if operator_id in self.signatures and operator_id in self.operators:
                    pub_g2 = self.operators[operator_id].get_pub_g2()
                    is_valid = self.signatures[operator_id].verify(pub_g2, message_bytes)
                    if not is_valid:
                        print(f"❌ Invalid signature from operator {operator_id}")
                        all_valid = False
                    else:
                        print(f"✅ Valid signature from operator {operator_id}")
            
            print(f"🎯 Aggregated signature verification: {'✅ VALID' if all_valid else '❌ INVALID'}")
            return all_valid

    # Example usage
    def signature_aggregation_example():
        print("🧪 BLS Signature Aggregation Example")
        print("=" * 40)
        
        aggregator = SignatureAggregator()
        
        # Create multiple operators with BLS key pairs
        operators = {}
        for i in range(5):
            operator_id = f"operator_{i}"
            key_pair = KeyPair()
            operators[operator_id] = key_pair
            aggregator.add_operator(operator_id, key_pair)
        
        # Message to sign
        message = b"Hello EigenLayer AVS!"
        
        # Collect signatures
        aggregator.collect_signatures(message)
        
        # Aggregate and verify with all operators
        print(f"\n📊 All Operators Verification:")
        aggregator.verify_aggregated_signature(message)
        
        # Aggregate and verify with subset
        print(f"\n📊 Subset Verification (first 3 operators):")
        subset = list(operators.keys())[:3]
        aggregator.verify_aggregated_signature(message, subset)

Advanced Error Handling
~~~~~~~~~~~~~~~~~~~~~~~

Robust Operation Patterns
-------------------------

.. code-block:: python

    import logging
    import time
    from functools import wraps
    from typing import Optional, Dict, Any

    class OperationResult:
        def __init__(self, success: bool, data: Any = None, error: str = None, tx_hash: str = None):
            self.success = success
            self.data = data
            self.error = error
            self.tx_hash = tx_hash

    class RobustEigenSDKClient:
        def __init__(self, clients):
            self.clients = clients
            self.logger = logging.getLogger(__name__)
        
        def safe_operation(self, operation_name: str, max_retries: int = 3, backoff_factor: float = 2.0):
            """Decorator for safe operations with retry logic."""
            def decorator(func):
                @wraps(func)
                def wrapper(*args, **kwargs):
                    last_exception = None
                    
                    for attempt in range(max_retries):
                        try:
                            self.logger.info(f"Attempting {operation_name} (attempt {attempt + 1}/{max_retries})")
                            result = func(*args, **kwargs)
                            self.logger.info(f"{operation_name} succeeded on attempt {attempt + 1}")
                            return OperationResult(True, data=result)
                            
                        except Exception as e:
                            last_exception = e
                            self.logger.warning(f"{operation_name} failed on attempt {attempt + 1}: {e}")
                            
                            if attempt < max_retries - 1:
                                wait_time = backoff_factor ** attempt
                                self.logger.info(f"Waiting {wait_time}s before retry...")
                                time.sleep(wait_time)
                    
                    # All attempts failed
                    error_msg = f"{operation_name} failed after {max_retries} attempts: {last_exception}"
                    self.logger.error(error_msg)
                    return OperationResult(False, error=error_msg)
                    
                return wrapper
            return decorator
        
        @safe_operation("Operator Registration", max_retries=3)
        def register_operator_safe(self, operator):
            """Safely register an operator with retries."""
            # Pre-flight checks
            if self.clients.el_reader.is_operator_registered(operator.address):
                raise ValueError("Operator already registered")
            
            # Validate operator data
            if not operator.address or not operator.earnings_receiver_address:
                raise ValueError("Invalid operator data")
            
            # Perform registration
            receipt = self.clients.el_writer.register_as_operator(operator)
            
            # Verify transaction success
            if receipt['status'] != 1:
                raise Exception(f"Transaction failed with status {receipt['status']}")
            
            return receipt
        
        @safe_operation("AVS Registration", max_retries=3)
        def register_avs_safe(self, private_key, salt, expiry, bls_key_pair, quorum_numbers, socket):
            """Safely register with AVS."""
            operator_address = self._get_address_from_private_key(private_key)
            
            # Pre-flight checks
            if not self.clients.el_reader.is_operator_registered(operator_address):
                raise ValueError("Operator not registered with EigenLayer")
            
            if self.clients.avs_registry_reader.is_operator_registered(operator_address):
                raise ValueError("Operator already registered with AVS")
            
            # Perform AVS registration
            receipt = self.clients.avs_registry_writer.register_operator_in_quorum_with_avs_registry_coordinator(
                operator_ecdsa_private_key=private_key,
                operator_to_avs_registration_sig_salt=salt,
                operator_to_avs_registration_sig_expiry=expiry,
                bls_key_pair=bls_key_pair,
                quorum_numbers=quorum_numbers,
                socket=socket
            )
            
            return receipt
        
        @safe_operation("Stake Update", max_retries=2)
        def update_stakes_safe(self, operators_per_quorum, quorum_numbers):
            """Safely update operator stakes."""
            # Validate inputs
            if len(operators_per_quorum) != len(quorum_numbers):
                raise ValueError("Mismatch between operators and quorum numbers")
            
            # Check all operators are valid addresses
            for quorum_operators in operators_per_quorum:
                for operator in quorum_operators:
                    if not self.clients.eth_http_client.isAddress(operator):
                        raise ValueError(f"Invalid operator address: {operator}")
            
            # Perform stake update
            receipt = self.clients.avs_registry_writer.update_stakes_of_entire_operator_set_for_quorums(
                operators_per_quorum=operators_per_quorum,
                quorum_numbers=quorum_numbers
            )
            
            return receipt
        
        def _get_address_from_private_key(self, private_key):
            """Extract address from private key."""
            from eth_account import Account
            account = Account.from_key(private_key)
            return account.address
        
        def health_check(self) -> Dict[str, Any]:
            """Comprehensive health check of all components."""
            health = {
                'timestamp': time.time(),
                'overall_status': 'healthy',
                'components': {}
            }
            
            # Check RPC connection
            try:
                latest_block = self.clients.eth_http_client.eth.block_number
                health['components']['rpc'] = {
                    'status': 'healthy',
                    'latest_block': latest_block
                }
            except Exception as e:
                health['components']['rpc'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health['overall_status'] = 'unhealthy'
            
            # Check contract connectivity
            try:
                quorum_count = self.clients.avs_registry_reader.get_quorum_count()
                health['components']['avs_contracts'] = {
                    'status': 'healthy',
                    'quorum_count': quorum_count
                }
            except Exception as e:
                health['components']['avs_contracts'] = {
                    'status': 'unhealthy',
                    'error': str(e)
                }
                health['overall_status'] = 'unhealthy'
            
            return health

Performance Optimization Examples
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Batch Operations
---------------

.. code-block:: python

    class BatchOperationManager:
        def __init__(self, clients, batch_size=50):
            self.clients = clients
            self.batch_size = batch_size
        
        def batch_operator_queries(self, operator_addresses):
            """Query multiple operators efficiently."""
            print(f"🔍 Batch querying {len(operator_addresses)} operators...")
            
            results = {}
            
            # Process in batches
            for i in range(0, len(operator_addresses), self.batch_size):
                batch = operator_addresses[i:i + self.batch_size]
                print(f"   Processing batch {i//self.batch_size + 1} ({len(batch)} operators)")
                
                batch_results = self._query_operator_batch(batch)
                results.update(batch_results)
            
            print(f"✅ Batch query complete: {len(results)} results")
            return results
        
        def _query_operator_batch(self, operator_addresses):
            """Query a batch of operators."""
            batch_results = {}
            
            for address in operator_addresses:
                try:
                    # Get basic operator info
                    is_registered_el = self.clients.el_reader.is_operator_registered(address)
                    is_registered_avs = self.clients.avs_registry_reader.is_operator_registered(address)
                    
                    operator_id = None
                    if is_registered_avs:
                        operator_id = self.clients.avs_registry_reader.get_operator_id(address)
                    
                    batch_results[address] = {
                        'el_registered': is_registered_el,
                        'avs_registered': is_registered_avs,
                        'operator_id': operator_id.hex() if operator_id else None
                    }
                    
                except Exception as e:
                    batch_results[address] = {
                        'error': str(e)
                    }
            
            return batch_results
        
        def efficient_stake_monitoring(self, quorum_numbers, poll_interval=60):
            """Efficiently monitor stakes across multiple quorums."""
            print(f"📊 Monitoring stakes for quorums {quorum_numbers}")
            
            previous_states = {}
            
            try:
                while True:
                    current_states = {}
                    
                    # Get all quorum states in one call
                    all_operators = self.clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block(quorum_numbers)
                    
                    for i, quorum_id in enumerate(quorum_numbers):
                        if i < len(all_operators) and all_operators[i]:
                            current_states[quorum_id] = {
                                op.operator: op.stake for op in all_operators[i]
                            }
                        else:
                            current_states[quorum_id] = {}
                    
                    # Compare with previous states
                    if previous_states:
                        for quorum_id in quorum_numbers:
                            self._report_stake_changes(
                                quorum_id,
                                previous_states.get(quorum_id, {}),
                                current_states[quorum_id]
                            )
                    
                    previous_states = current_states
                    time.sleep(poll_interval)
                    
            except KeyboardInterrupt:
                print("\n⏹️  Stake monitoring stopped")
        
        def _report_stake_changes(self, quorum_id, old_state, new_state):
            """Report changes in stake for a quorum."""
            # Calculate total stake change
            old_total = sum(old_state.values())
            new_total = sum(new_state.values())
            total_change = (new_total - old_total) / 10**18
            
            if abs(total_change) > 0.01:  # Only report significant changes
                print(f"📈 Quorum {quorum_id} total stake change: {total_change:+.2f} ETH")
                
            # Report individual operator changes
            for operator in set(old_state.keys()) | set(new_state.keys()):
                old_stake = old_state.get(operator, 0)
                new_stake = new_state.get(operator, 0)
                
                if old_stake != new_stake:
                    change = (new_stake - old_stake) / 10**18
                    if abs(change) > 0.01:  # Only report significant changes
                        print(f"   {operator}: {change:+.2f} ETH")

    # Usage examples
    def run_advanced_examples():
        """Run all advanced examples."""
        print("🚀 EigenSDK Advanced Examples")
        print("=" * 50)
        
        # Load configuration (you'll need to set these up)
        config = BuildAllConfig(
            # ... your configuration
        )
        private_key = os.getenv('PRIVATE_KEY')
        
        # Initialize clients
        clients = build_all(config, private_key)
        
        # Example 1: Complete operator setup
        print("\n1️⃣  Complete Operator Setup Example")
        operator_manager = AVSOperatorManager(config, private_key)
        operator_manager.initialize()
        
        # Example 2: Multi-quorum operations
        print("\n2️⃣  Multi-Quorum Operations Example")
        multi_quorum = MultiQuorumManager(clients)
        multi_quorum.get_quorum_overview()
        
        # Example 3: Signature aggregation
        print("\n3️⃣  Signature Aggregation Example")
        signature_aggregation_example()
        
        # Example 4: Robust operations
        print("\n4️⃣  Robust Operations Example")
        robust_client = RobustEigenSDKClient(clients)
        health = robust_client.health_check()
        print(f"Health check result: {health['overall_status']}")
        
        # Example 5: Batch operations
        print("\n5️⃣  Batch Operations Example")
        batch_manager = BatchOperationManager(clients)
        # batch_manager.efficient_stake_monitoring([0, 1])

    if __name__ == "__main__":
        run_advanced_examples() 