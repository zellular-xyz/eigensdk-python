.. _security:

Security & Best Practices
=========================

This guide covers essential security considerations and best practices for using EigenSDK-Python in production environments.

Private Key Management
~~~~~~~~~~~~~~~~~~~~~

Critical Security Principles
----------------------------

.. warning::
   
   **Never hardcode private keys in your source code.** Always use secure methods for key storage and access.

Environment Variables
---------------------

**Recommended approach for development and testing:**

.. code-block:: shell

    # Create .env file (add to .gitignore!)
    $ echo "PRIVATE_KEY=0x..." > .env
    $ echo "ETH_RPC_URL=https://..." >> .env
    $ echo ".env" >> .gitignore

.. code-block:: python

    import os
    from dotenv import load_dotenv

    load_dotenv()
    private_key = os.getenv('PRIVATE_KEY')
    
    # Validate key exists and format
    if not private_key:
        raise ValueError("PRIVATE_KEY environment variable not set")
    
    if not private_key.startswith('0x'):
        private_key = '0x' + private_key

Hardware Security Modules (HSM)
-------------------------------

**For production environments:**

.. code-block:: python

    # Example using AWS KMS
    import boto3
    from eth_account import Account

    def get_private_key_from_kms(key_id):
        kms = boto3.client('kms')
        response = kms.decrypt(
            CiphertextBlob=encrypted_key,
            KeyId=key_id
        )
        return response['Plaintext'].decode()

    # Use with EigenSDK
    private_key = get_private_key_from_kms('your-kms-key-id')
    clients = build_all(config, private_key)

Key Rotation Strategy
--------------------

.. code-block:: python

    # Implement key rotation for long-running services
    class SecureKeyManager:
        def __init__(self, primary_key, backup_key=None):
            self.primary_key = primary_key
            self.backup_key = backup_key
            self.last_rotation = time.time()
            self.rotation_interval = 30 * 24 * 3600  # 30 days
        
        def should_rotate(self):
            return time.time() - self.last_rotation > self.rotation_interval
        
        def get_current_key(self):
            if self.should_rotate() and self.backup_key:
                self.rotate_keys()
            return self.primary_key
        
        def rotate_keys(self):
            # Implement your key rotation logic
            pass

Network Security
~~~~~~~~~~~~~~~

RPC Endpoint Security
--------------------

**Use authenticated and rate-limited RPC endpoints:**

.. code-block:: python

    # Secure RPC configuration
    RPC_CONFIG = {
        'timeout': 30,
        'retries': 3,
        'headers': {
            'Authorization': f'Bearer {os.getenv("RPC_API_KEY")}',
            'User-Agent': 'YourAVS/1.0'
        }
    }

    provider = Web3.HTTPProvider(
        rpc_url,
        request_kwargs=RPC_CONFIG
    )

**Fallback RPC endpoints:**

.. code-block:: python

    class SecureWeb3Provider:
        def __init__(self, primary_rpc, fallback_rpcs=None):
            self.primary_rpc = primary_rpc
            self.fallback_rpcs = fallback_rpcs or []
            self.current_provider_index = 0
        
        def get_web3_instance(self):
            rpcs = [self.primary_rpc] + self.fallback_rpcs
            
            for i, rpc_url in enumerate(rpcs):
                try:
                    w3 = Web3(Web3.HTTPProvider(rpc_url))
                    if w3.isConnected():
                        self.current_provider_index = i
                        return w3
                except Exception as e:
                    logger.warning(f"RPC {rpc_url} failed: {e}")
                    continue
            
            raise ConnectionError("All RPC endpoints failed")

TLS and Certificate Validation
------------------------------

.. code-block:: python

    import ssl
    import certifi

    # Ensure secure TLS connections
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    # Use with requests
    import requests
    session = requests.Session()
    session.verify = certifi.where()

Contract Interaction Security
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Address Validation
------------------

.. code-block:: python

    from web3 import Web3

    def validate_contract_address(w3, address, expected_code_hash=None):
        """Validate contract address and optionally verify code hash."""
        
        # Basic validation
        if not Web3.isAddress(address):
            raise ValueError(f"Invalid Ethereum address: {address}")
        
        # Check if contract exists
        code = w3.eth.get_code(address)
        if code == b'':
            raise ValueError(f"No contract deployed at address: {address}")
        
        # Optional: Verify contract code hash
        if expected_code_hash:
            actual_hash = w3.keccak(code).hex()
            if actual_hash != expected_code_hash:
                raise ValueError(f"Contract code hash mismatch at {address}")
        
        return True

Transaction Security
-------------------

.. code-block:: python

    def build_secure_transaction(w3, contract_function, from_address, private_key):
        """Build transaction with security checks."""
        
        # Get current network state
        nonce = w3.eth.get_transaction_count(from_address, 'pending')
        gas_price = w3.eth.gas_price
        
        # Build transaction with reasonable limits
        transaction = contract_function.buildTransaction({
            'from': from_address,
            'nonce': nonce,
            'gasPrice': min(gas_price * 2, w3.toWei('100', 'gwei')),  # Cap gas price
            'gas': 1000000,  # Conservative gas limit
        })
        
        # Estimate gas more precisely
        try:
            estimated_gas = w3.eth.estimate_gas(transaction)
            transaction['gas'] = int(estimated_gas * 1.2)  # 20% buffer
        except Exception as e:
            logger.warning(f"Gas estimation failed: {e}")
            # Keep conservative default
        
        # Sign and validate
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
        
        # Final validation
        try:
            w3.eth.call(transaction)  # Simulate transaction
        except Exception as e:
            raise ValueError(f"Transaction simulation failed: {e}")
        
        return signed_txn

Input Validation and Sanitization
---------------------------------

.. code-block:: python

    def validate_operator_registration_input(operator_data):
        """Validate operator registration data."""
        
        required_fields = [
            'address', 'earnings_receiver_address', 
            'delegation_approver_address', 'staker_opt_out_window_blocks'
        ]
        
        for field in required_fields:
            if field not in operator_data:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate addresses
        address_fields = [
            'address', 'earnings_receiver_address', 'delegation_approver_address'
        ]
        for field in address_fields:
            if not Web3.isAddress(operator_data[field]):
                raise ValueError(f"Invalid address in field {field}")
        
        # Validate numeric fields
        if not isinstance(operator_data['staker_opt_out_window_blocks'], int):
            raise ValueError("staker_opt_out_window_blocks must be an integer")
        
        if operator_data['staker_opt_out_window_blocks'] < 0:
            raise ValueError("staker_opt_out_window_blocks cannot be negative")
        
        # Validate metadata URL if provided
        if 'metadata_url' in operator_data:
            url = operator_data['metadata_url']
            if url and not (url.startswith('https://') or url.startswith('http://')):
                raise ValueError("metadata_url must be a valid HTTP(S) URL")
        
        return True

Operational Security
~~~~~~~~~~~~~~~~~~~

Monitoring and Logging
----------------------

.. code-block:: python

    import logging
    import structlog
    from datetime import datetime

    # Configure secure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/eigensdk/app.log'),
            logging.StreamHandler()
        ]
    )

    # Use structured logging for security events
    security_logger = structlog.get_logger("security")

    def log_security_event(event_type, details):
        security_logger.info(
            "security_event",
            event_type=event_type,
            timestamp=datetime.utcnow().isoformat(),
            details=details
        )

    # Example usage
    def register_operator_with_logging(clients, operator):
        log_security_event("operator_registration_attempt", {
            "operator_address": operator.address,
            "earnings_receiver": operator.earnings_receiver_address
        })
        
        try:
            receipt = clients.el_writer.register_as_operator(operator)
            log_security_event("operator_registration_success", {
                "operator_address": operator.address,
                "transaction_hash": receipt['transactionHash'].hex()
            })
            return receipt
        except Exception as e:
            log_security_event("operator_registration_failure", {
                "operator_address": operator.address,
                "error": str(e)
            })
            raise

Rate Limiting and DOS Protection
-------------------------------

.. code-block:: python

    import time
    from collections import defaultdict, deque
    from functools import wraps

    class RateLimiter:
        def __init__(self, max_requests=100, window_seconds=60):
            self.max_requests = max_requests
            self.window_seconds = window_seconds
            self.requests = defaultdict(deque)
        
        def is_allowed(self, identifier):
            now = time.time()
            window_start = now - self.window_seconds
            
            # Clean old requests
            while (self.requests[identifier] and 
                   self.requests[identifier][0] < window_start):
                self.requests[identifier].popleft()
            
            # Check if under limit
            if len(self.requests[identifier]) >= self.max_requests:
                return False
            
            # Add current request
            self.requests[identifier].append(now)
            return True

    # Rate limiting decorator
    rate_limiter = RateLimiter(max_requests=10, window_seconds=60)

    def rate_limited(identifier_func):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                identifier = identifier_func(*args, **kwargs)
                if not rate_limiter.is_allowed(identifier):
                    raise Exception(f"Rate limit exceeded for {identifier}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    # Example usage
    @rate_limited(lambda clients, address: address)
    def get_operator_info(clients, operator_address):
        return clients.avs_registry_reader.get_operator_info(operator_address)

Error Handling and Information Disclosure
-----------------------------------------

.. code-block:: python

    class SecurityError(Exception):
        """Custom exception that doesn't leak sensitive information."""
        pass

    def secure_error_handler(func):
        """Decorator to handle errors securely."""
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Log detailed error internally
                logger.error(f"Error in {func.__name__}: {str(e)}", exc_info=True)
                
                # Return generic error to user
                raise SecurityError("Operation failed. Please check logs for details.")
        return wrapper

    @secure_error_handler
    def sensitive_operation(clients, private_key):
        # Your sensitive operation here
        pass

Production Deployment
~~~~~~~~~~~~~~~~~~~~

Environment Separation
----------------------

.. code-block:: yaml

    # docker-compose.production.yml
    version: '3.8'
    services:
      eigensdk-app:
        image: your-eigensdk-app:latest
        environment:
          - ENVIRONMENT=production
          - LOG_LEVEL=INFO
          - PRIVATE_KEY_SOURCE=kms
        volumes:
          - /var/log/eigensdk:/app/logs:rw
        networks:
          - internal
        restart: unless-stopped
        
        # Security options
        security_opt:
          - no-new-privileges:true
        read_only: true
        tmpfs:
          - /tmp
        
    networks:
      internal:
        internal: true

Secrets Management
-----------------

.. code-block:: python

    # Production secrets management example
    import boto3
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential

    class ProductionSecretsManager:
        def __init__(self, provider='aws'):
            self.provider = provider
            
        def get_secret(self, secret_name):
            if self.provider == 'aws':
                return self._get_aws_secret(secret_name)
            elif self.provider == 'azure':
                return self._get_azure_secret(secret_name)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        
        def _get_aws_secret(self, secret_name):
            session = boto3.session.Session()
            client = session.client('secretsmanager')
            response = client.get_secret_value(SecretId=secret_name)
            return response['SecretString']
        
        def _get_azure_secret(self, secret_name):
            credential = DefaultAzureCredential()
            client = SecretClient(
                vault_url="https://your-vault.vault.azure.net/",
                credential=credential
            )
            secret = client.get_secret(secret_name)
            return secret.value

Health Checks and Monitoring
----------------------------

.. code-block:: python

    from flask import Flask, jsonify
    import psutil
    import time

    app = Flask(__name__)

    @app.route('/health')
    def health_check():
        """Comprehensive health check endpoint."""
        health_status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'checks': {}
        }
        
        try:
            # Check RPC connectivity
            w3 = get_web3_instance()
            latest_block = w3.eth.block_number
            health_status['checks']['rpc'] = {
                'status': 'ok',
                'latest_block': latest_block
            }
        except Exception as e:
            health_status['checks']['rpc'] = {
                'status': 'error',
                'error': str(e)
            }
            health_status['status'] = 'unhealthy'
        
        # Check system resources
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        
        health_status['checks']['resources'] = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'status': 'ok' if cpu_percent < 80 and memory_percent < 80 else 'warning'
        }
        
        return jsonify(health_status)

Security Checklist
~~~~~~~~~~~~~~~~~~

**Pre-Deployment Security Checklist:**

.. code-block:: text

    □ Private keys stored securely (HSM/KMS, not in code)
    □ Environment variables configured properly
    □ RPC endpoints use authenticated/rate-limited services
    □ Contract addresses validated and verified
    □ Input validation implemented for all user inputs
    □ Rate limiting configured for public endpoints
    □ Comprehensive logging and monitoring in place
    □ Error handling doesn't leak sensitive information
    □ TLS/SSL properly configured for all external communications
    □ Network security (firewalls, VPNs) configured
    □ Regular security updates and dependency scanning
    □ Incident response plan documented
    □ Backup and recovery procedures tested
    □ Access controls and authentication implemented
    □ Security testing and auditing completed

**Runtime Security Monitoring:**

.. code-block:: python

    # Example security monitoring
    class SecurityMonitor:
        def __init__(self):
            self.failed_attempts = defaultdict(int)
            self.suspicious_patterns = []
        
        def log_failed_transaction(self, address, error):
            self.failed_attempts[address] += 1
            if self.failed_attempts[address] > 5:
                self.alert_security_team(f"Multiple failures from {address}")
        
        def check_gas_price_anomaly(self, gas_price):
            if gas_price > self.get_max_reasonable_gas_price():
                self.alert_security_team(f"Unusually high gas price: {gas_price}")
        
        def alert_security_team(self, message):
            # Implement your alerting mechanism
            logger.critical(f"SECURITY ALERT: {message}")

Regular Security Maintenance
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Weekly Tasks:**
- Review security logs for anomalies
- Update dependencies to latest secure versions
- Verify backup integrity
- Check certificate expiration dates

**Monthly Tasks:**
- Rotate access keys and tokens
- Review and update security policies
- Conduct security scans
- Test incident response procedures

**Quarterly Tasks:**
- Security audit and penetration testing
- Review and update threat model
- Security training for team members
- Disaster recovery testing 