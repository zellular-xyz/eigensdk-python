.. _performance:

Performance Guide
=================

This guide covers performance optimization techniques, memory management, and best practices for high-throughput operations with EigenSDK-Python.

RPC Optimization
~~~~~~~~~~~~~~~~

Connection Pooling and Caching
------------------------------

.. code-block:: python

    from web3 import Web3
    from web3.providers.rpc import HTTPProvider
    from web3.middleware import geth_poa_middleware
    import threading
    from functools import lru_cache
    import time

    class OptimizedWeb3Provider:
        def __init__(self, rpc_urls, pool_size=10):
            self.rpc_urls = rpc_urls
            self.pool_size = pool_size
            self._connections = {}
            self._lock = threading.Lock()
            self._current_url_index = 0
        
        def get_connection(self):
            """Get an optimized Web3 connection with connection pooling."""
            thread_id = threading.get_ident()
            
            with self._lock:
                if thread_id not in self._connections:
                    rpc_url = self.rpc_urls[self._current_url_index % len(self.rpc_urls)]
                    self._current_url_index += 1
                    
                    provider = HTTPProvider(
                        rpc_url,
                        request_kwargs={
                            'timeout': 30,
                            'pool_connections': self.pool_size,
                            'pool_maxsize': self.pool_size,
                            'max_retries': 3,
                        }
                    )
                    
                    w3 = Web3(provider)
                    # Add middleware for better performance
                    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                    
                    self._connections[thread_id] = w3
                
                return self._connections[thread_id]

    # Caching frequently accessed data
    class CachedContractReader:
        def __init__(self, clients, cache_ttl=300):  # 5 minutes cache
            self.clients = clients
            self.cache_ttl = cache_ttl
            self._cache = {}
        
        @lru_cache(maxsize=1000)
        def is_operator_registered(self, operator_address):
            """Cached operator registration check."""
            cache_key = f"is_registered_{operator_address}"
            now = time.time()
            
            if cache_key in self._cache:
                cached_time, result = self._cache[cache_key]
                if now - cached_time < self.cache_ttl:
                    return result
            
            # Cache miss - fetch from contract
            result = self.clients.el_reader.is_operator_registered(operator_address)
            self._cache[cache_key] = (now, result)
            return result
        
        def clear_cache(self, pattern=None):
            """Clear cache entries matching pattern."""
            if pattern is None:
                self._cache.clear()
            else:
                keys_to_remove = [k for k in self._cache.keys() if pattern in k]
                for key in keys_to_remove:
                    del self._cache[key]

Batch RPC Calls
---------------

.. code-block:: python

    from web3.batch import Batch
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import asyncio

    class BatchProcessor:
        def __init__(self, clients, max_workers=5):
            self.clients = clients
            self.max_workers = max_workers
        
        def batch_operator_queries(self, operator_addresses, batch_size=50):
            """Process operator queries in batches for better performance."""
            results = {}
            
            # Split addresses into batches
            batches = [
                operator_addresses[i:i + batch_size] 
                for i in range(0, len(operator_addresses), batch_size)
            ]
            
            # Process batches concurrently
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_batch = {
                    executor.submit(self._process_batch, batch): batch 
                    for batch in batches
                }
                
                for future in as_completed(future_to_batch):
                    batch_results = future.result()
                    results.update(batch_results)
            
            return results
        
        def _process_batch(self, operator_addresses):
            """Process a single batch of operator addresses."""
            batch_results = {}
            
            # Use Web3 batch requests for better RPC efficiency
            w3 = self.clients.eth_http_client
            
            with w3.batch_requests() as batch:
                batch_requests = []
                
                for address in operator_addresses:
                    # Add multiple contract calls to the batch
                    el_request = batch.add(
                        self.clients.el_reader.is_operator_registered, address
                    )
                    avs_request = batch.add(
                        self.clients.avs_registry_reader.is_operator_registered, address
                    )
                    
                    batch_requests.append((address, el_request, avs_request))
                
                # Execute all requests in batch
                results = batch.execute()
                
                # Process results
                for i, (address, el_req, avs_req) in enumerate(batch_requests):
                    try:
                        batch_results[address] = {
                            'el_registered': results[i * 2],
                            'avs_registered': results[i * 2 + 1],
                            'timestamp': time.time()
                        }
                    except Exception as e:
                        batch_results[address] = {'error': str(e)}
            
            return batch_results

Memory Management
~~~~~~~~~~~~~~~~~

Efficient Data Structures
-------------------------

.. code-block:: python

    import sys
    from dataclasses import dataclass, field
    from typing import Dict, List, Optional, NamedTuple
    import gc
    from collections import deque
    import weakref

    # Use slots for memory-efficient classes
    @dataclass
    class OptimizedOperatorInfo:
        __slots__ = ['address', 'stake', 'quorum_id', 'last_update']
        
        address: str
        stake: int
        quorum_id: int
        last_update: float

    # Use NamedTuple for immutable data
    class StakeInfo(NamedTuple):
        operator: str
        stake: int
        block_number: int

    class MemoryEfficientQuorumManager:
        def __init__(self, max_history=1000):
            self.max_history = max_history
            # Use deque for efficient FIFO operations
            self.stake_history = deque(maxlen=max_history)
            # Use weak references to avoid memory leaks
            self._observers = weakref.WeakSet()
        
        def add_stake_update(self, stake_info: StakeInfo):
            """Add stake update with memory management."""
            self.stake_history.append(stake_info)
            
            # Trigger garbage collection periodically
            if len(self.stake_history) % 100 == 0:
                self._cleanup_memory()
        
        def get_recent_stakes(self, limit=100):
            """Get recent stakes efficiently."""
            return list(self.stake_history)[-limit:]
        
        def _cleanup_memory(self):
            """Periodic memory cleanup."""
            gc.collect()
            
            # Log memory usage
            memory_mb = sys.getsizeof(self.stake_history) / (1024 * 1024)
            print(f"Stake history memory usage: {memory_mb:.2f} MB")

Large Dataset Processing
------------------------

.. code-block:: python

    import mmap
    import json
    from itertools import islice
    import psutil

    class LargeDatasetProcessor:
        def __init__(self, clients, memory_threshold_mb=1000):
            self.clients = clients
            self.memory_threshold_mb = memory_threshold_mb
        
        def process_all_operators(self, chunk_size=100):
            """Process all operators without loading everything into memory."""
            # Monitor memory usage
            process = psutil.Process()
            
            all_operators = self._get_all_operator_addresses()
            
            for chunk in self._chunked_iterable(all_operators, chunk_size):
                # Check memory usage before processing
                memory_mb = process.memory_info().rss / (1024 * 1024)
                if memory_mb > self.memory_threshold_mb:
                    print(f"⚠️ High memory usage: {memory_mb:.1f}MB, triggering cleanup")
                    gc.collect()
                
                # Process chunk
                yield from self._process_operator_chunk(chunk)
        
        def _get_all_operator_addresses(self):
            """Generator to yield operator addresses without loading all at once."""
            # Get quorum count
            quorum_count = self.clients.avs_registry_reader.get_quorum_count()
            
            seen_operators = set()
            
            for quorum_id in range(quorum_count):
                try:
                    operators = self.clients.avs_registry_reader.get_operator_addrs_in_quorums_at_current_block([quorum_id])
                    if operators and operators[0]:
                        for operator_addr in operators[0]:
                            if operator_addr not in seen_operators:
                                seen_operators.add(operator_addr)
                                yield operator_addr
                except Exception as e:
                    print(f"Error fetching quorum {quorum_id}: {e}")
        
        def _chunked_iterable(self, iterable, chunk_size):
            """Yield successive chunks from iterable."""
            iterator = iter(iterable)
            while True:
                chunk = list(islice(iterator, chunk_size))
                if not chunk:
                    break
                yield chunk
        
        def _process_operator_chunk(self, operator_addresses):
            """Process a chunk of operators and yield results."""
            for address in operator_addresses:
                try:
                    # Process individual operator
                    result = self._process_single_operator(address)
                    yield result
                except Exception as e:
                    yield {'address': address, 'error': str(e)}
        
        def _process_single_operator(self, address):
            """Process a single operator efficiently."""
            return {
                'address': address,
                'el_registered': self.clients.el_reader.is_operator_registered(address),
                'avs_registered': self.clients.avs_registry_reader.is_operator_registered(address),
            }

Concurrency and Parallelization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thread-Safe Operations
----------------------

.. code-block:: python

    import threading
    from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
    from threading import Lock, RLock
    import queue
    import multiprocessing as mp

    class ThreadSafeOperationManager:
        def __init__(self, clients):
            self.clients = clients
            self._lock = RLock()  # Reentrant lock for nested calls
            self._operation_count = 0
            self._active_operations = set()
        
        def safe_read_operation(self, operation_id, func, *args, **kwargs):
            """Execute read operation safely with locking."""
            with self._lock:
                self._active_operations.add(operation_id)
                self._operation_count += 1
            
            try:
                result = func(*args, **kwargs)
                return {'success': True, 'data': result, 'operation_id': operation_id}
            except Exception as e:
                return {'success': False, 'error': str(e), 'operation_id': operation_id}
            finally:
                with self._lock:
                    self._active_operations.discard(operation_id)
        
        def get_operation_stats(self):
            """Get thread-safe operation statistics."""
            with self._lock:
                return {
                    'total_operations': self._operation_count,
                    'active_operations': len(self._active_operations),
                    'active_operation_ids': list(self._active_operations)
                }

    class ParallelProcessor:
        def __init__(self, clients, max_workers=None):
            self.clients = clients
            self.max_workers = max_workers or min(32, (mp.cpu_count() or 1) + 4)
        
        def parallel_operator_analysis(self, operator_addresses):
            """Analyze operators in parallel for maximum performance."""
            results = []
            failed_operations = []
            
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_address = {
                    executor.submit(self._analyze_operator, addr): addr 
                    for addr in operator_addresses
                }
                
                # Collect results as they complete
                for future in as_completed(future_to_address):
                    address = future_to_address[future]
                    try:
                        result = future.result(timeout=30)  # 30 second timeout
                        results.append(result)
                    except Exception as e:
                        failed_operations.append({'address': address, 'error': str(e)})
            
            return {
                'successful_results': results,
                'failed_operations': failed_operations,
                'success_rate': len(results) / len(operator_addresses) if operator_addresses else 0
            }
        
        def _analyze_operator(self, operator_address):
            """Analyze a single operator (thread-safe operation)."""
            # Each thread should have its own client connections
            # This is a simplified example - in practice, you'd want connection pooling
            
            analysis = {
                'address': operator_address,
                'timestamp': time.time(),
            }
            
            try:
                # Basic registration checks
                analysis['el_registered'] = self.clients.el_reader.is_operator_registered(operator_address)
                analysis['avs_registered'] = self.clients.avs_registry_reader.is_operator_registered(operator_address)
                
                # Additional analysis if registered
                if analysis['avs_registered']:
                    operator_id = self.clients.avs_registry_reader.get_operator_id(operator_address)
                    analysis['operator_id'] = operator_id.hex()
                    
                    # Get stake information across quorums
                    quorum_count = self.clients.avs_registry_reader.get_quorum_count()
                    stake_info = {}
                    
                    for quorum_id in range(min(quorum_count, 5)):  # Limit to first 5 quorums
                        try:
                            operators = self.clients.avs_registry_reader.get_operators_stake_in_quorums_at_current_block([quorum_id])
                            if operators and operators[0]:
                                for op in operators[0]:
                                    if op.operator.lower() == operator_address.lower():
                                        stake_info[f'quorum_{quorum_id}'] = op.stake
                                        break
                        except Exception:
                            continue  # Skip failed quorum queries
                    
                    analysis['stake_info'] = stake_info
                
                return analysis
                
            except Exception as e:
                analysis['error'] = str(e)
                return analysis

Caching Strategies
~~~~~~~~~~~~~~~~~~

Multi-Level Caching
-------------------

.. code-block:: python

    import redis
    import pickle
    from typing import Any, Optional
    import hashlib

    class MultiLevelCache:
        def __init__(self, redis_client=None, memory_cache_size=1000, ttl=300):
            self.redis_client = redis_client
            self.memory_cache = {}
            self.memory_cache_size = memory_cache_size
            self.ttl = ttl
            self._access_order = deque()
        
        def get(self, key: str) -> Optional[Any]:
            """Get value from cache (memory first, then Redis)."""
            # Try memory cache first
            if key in self.memory_cache:
                value, expiry = self.memory_cache[key]
                if time.time() < expiry:
                    # Move to end (LRU)
                    self._access_order.remove(key)
                    self._access_order.append(key)
                    return value
                else:
                    # Expired
                    del self.memory_cache[key]
                    self._access_order.remove(key)
            
            # Try Redis cache
            if self.redis_client:
                try:
                    cached_data = self.redis_client.get(key)
                    if cached_data:
                        value = pickle.loads(cached_data)
                        # Store in memory cache for faster access
                        self._store_in_memory(key, value)
                        return value
                except Exception as e:
                    print(f"Redis cache error: {e}")
            
            return None
        
        def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
            """Set value in both memory and Redis cache."""
            ttl = ttl or self.ttl
            
            # Store in memory cache
            self._store_in_memory(key, value, ttl)
            
            # Store in Redis cache
            if self.redis_client:
                try:
                    serialized_value = pickle.dumps(value)
                    self.redis_client.setex(key, ttl, serialized_value)
                except Exception as e:
                    print(f"Redis cache set error: {e}")
        
        def _store_in_memory(self, key: str, value: Any, ttl: Optional[int] = None):
            """Store value in memory cache with LRU eviction."""
            ttl = ttl or self.ttl
            expiry = time.time() + ttl
            
            # Remove if already exists
            if key in self.memory_cache:
                self._access_order.remove(key)
            
            # Add to cache
            self.memory_cache[key] = (value, expiry)
            self._access_order.append(key)
            
            # Evict if necessary
            while len(self.memory_cache) > self.memory_cache_size:
                oldest_key = self._access_order.popleft()
                del self.memory_cache[oldest_key]

    class SmartCachingClient:
        def __init__(self, clients, cache=None):
            self.clients = clients
            self.cache = cache or MultiLevelCache()
        
        def get_operator_info_cached(self, operator_address: str):
            """Get operator info with intelligent caching."""
            cache_key = f"operator_info_{operator_address}"
            
            # Try cache first
            cached_result = self.cache.get(cache_key)
            if cached_result:
                return cached_result
            
            # Cache miss - fetch from contracts
            try:
                operator_info = {
                    'address': operator_address,
                    'el_registered': self.clients.el_reader.is_operator_registered(operator_address),
                    'avs_registered': self.clients.avs_registry_reader.is_operator_registered(operator_address),
                    'timestamp': time.time()
                }
                
                if operator_info['avs_registered']:
                    operator_id = self.clients.avs_registry_reader.get_operator_id(operator_address)
                    operator_info['operator_id'] = operator_id.hex()
                
                # Cache the result
                # Use shorter TTL for dynamic data, longer for static data
                cache_ttl = 60 if operator_info['avs_registered'] else 300
                self.cache.set(cache_key, operator_info, cache_ttl)
                
                return operator_info
                
            except Exception as e:
                # Cache errors too (with shorter TTL to allow retries)
                error_result = {'error': str(e), 'timestamp': time.time()}
                self.cache.set(cache_key, error_result, 30)
                return error_result

Performance Monitoring
~~~~~~~~~~~~~~~~~~~~~~

Real-time Metrics
-----------------

.. code-block:: python

    import time
    import psutil
    from dataclasses import dataclass, field
    from typing import Dict, List
    from collections import defaultdict, deque

    @dataclass
    class PerformanceMetrics:
        operation_count: int = 0
        total_duration: float = 0.0
        error_count: int = 0
        memory_usage_mb: float = 0.0
        rpc_calls: int = 0
        cache_hits: int = 0
        cache_misses: int = 0
        
        def average_duration(self) -> float:
            return self.total_duration / self.operation_count if self.operation_count > 0 else 0.0
        
        def error_rate(self) -> float:
            return self.error_count / self.operation_count if self.operation_count > 0 else 0.0
        
        def cache_hit_rate(self) -> float:
            total_cache_requests = self.cache_hits + self.cache_misses
            return self.cache_hits / total_cache_requests if total_cache_requests > 0 else 0.0

    class PerformanceMonitor:
        def __init__(self, window_size=1000):
            self.window_size = window_size
            self.metrics = PerformanceMetrics()
            self.operation_times = deque(maxlen=window_size)
            self.recent_operations = defaultdict(lambda: deque(maxlen=100))
        
        def time_operation(self, operation_name: str):
            """Context manager for timing operations."""
            return OperationTimer(self, operation_name)
        
        def record_operation(self, operation_name: str, duration: float, success: bool = True):
            """Record operation metrics."""
            self.metrics.operation_count += 1
            self.metrics.total_duration += duration
            self.operation_times.append(duration)
            self.recent_operations[operation_name].append({
                'duration': duration,
                'success': success,
                'timestamp': time.time()
            })
            
            if not success:
                self.metrics.error_count += 1
        
        def record_rpc_call(self):
            """Record RPC call."""
            self.metrics.rpc_calls += 1
        
        def record_cache_hit(self):
            """Record cache hit."""
            self.metrics.cache_hits += 1
        
        def record_cache_miss(self):
            """Record cache miss."""
            self.metrics.cache_misses += 1
        
        def update_memory_usage(self):
            """Update current memory usage."""
            process = psutil.Process()
            self.metrics.memory_usage_mb = process.memory_info().rss / (1024 * 1024)
        
        def get_performance_report(self) -> Dict:
            """Get comprehensive performance report."""
            self.update_memory_usage()
            
            # Calculate percentiles for operation times
            sorted_times = sorted(self.operation_times)
            percentiles = {}
            if sorted_times:
                percentiles = {
                    'p50': self._percentile(sorted_times, 50),
                    'p90': self._percentile(sorted_times, 90),
                    'p95': self._percentile(sorted_times, 95),
                    'p99': self._percentile(sorted_times, 99),
                }
            
            # Operation-specific statistics
            operation_stats = {}
            for op_name, operations in self.recent_operations.items():
                if operations:
                    durations = [op['duration'] for op in operations]
                    successes = [op['success'] for op in operations]
                    
                    operation_stats[op_name] = {
                        'count': len(operations),
                        'avg_duration': sum(durations) / len(durations),
                        'success_rate': sum(successes) / len(successes),
                        'recent_operations': len(operations)
                    }
            
            return {
                'overall_metrics': {
                    'total_operations': self.metrics.operation_count,
                    'average_duration_ms': self.metrics.average_duration() * 1000,
                    'error_rate': self.metrics.error_rate(),
                    'memory_usage_mb': self.metrics.memory_usage_mb,
                    'rpc_calls': self.metrics.rpc_calls,
                    'cache_hit_rate': self.metrics.cache_hit_rate()
                },
                'percentiles_ms': {k: v * 1000 for k, v in percentiles.items()},
                'operation_stats': operation_stats,
                'timestamp': time.time()
            }
        
        def _percentile(self, sorted_data, percentile):
            """Calculate percentile of sorted data."""
            if not sorted_data:
                return 0.0
            
            index = (percentile / 100.0) * (len(sorted_data) - 1)
            if index.is_integer():
                return sorted_data[int(index)]
            else:
                lower = sorted_data[int(index)]
                upper = sorted_data[int(index) + 1]
                return lower + (upper - lower) * (index - int(index))

    class OperationTimer:
        def __init__(self, monitor: PerformanceMonitor, operation_name: str):
            self.monitor = monitor
            self.operation_name = operation_name
            self.start_time = None
        
        def __enter__(self):
            self.start_time = time.time()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            duration = time.time() - self.start_time
            success = exc_type is None
            self.monitor.record_operation(self.operation_name, duration, success)

    # Usage example
    class HighPerformanceEigenSDKClient:
        def __init__(self, clients):
            self.clients = clients
            self.monitor = PerformanceMonitor()
            self.cache = MultiLevelCache()
        
        def optimized_bulk_operation(self, operator_addresses):
            """Example of optimized bulk operation with monitoring."""
            with self.monitor.time_operation("bulk_operator_analysis"):
                # Use all optimization techniques
                processor = ParallelProcessor(self.clients)
                results = processor.parallel_operator_analysis(operator_addresses)
                
                # Record additional metrics
                for _ in range(len(operator_addresses)):
                    self.monitor.record_rpc_call()
                
                return results
        
        def get_performance_dashboard(self):
            """Get real-time performance dashboard."""
            return {
                'performance': self.monitor.get_performance_report(),
                'system_info': {
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'disk_usage': psutil.disk_usage('/').percent
                }
            }

Best Practices Summary
~~~~~~~~~~~~~~~~~~~~~~

**Performance Checklist:**

.. code-block:: text

    □ Use connection pooling for RPC endpoints
    □ Implement multi-level caching (memory + Redis)
    □ Process operations in batches
    □ Use parallel processing for independent operations
    □ Monitor memory usage and implement cleanup
    □ Use efficient data structures (slots, NamedTuple)
    □ Implement proper error handling and retries
    □ Cache frequently accessed contract data
    □ Use generators for large datasets
    □ Monitor performance metrics in real-time
    □ Set appropriate timeouts for all operations
    □ Use weak references to prevent memory leaks

**Optimization Tips:**

1. **Batch RPC calls** whenever possible
2. **Cache static data** (contract addresses, operator IDs) for longer periods
3. **Cache dynamic data** (stakes, registrations) for shorter periods
4. **Use threading** for I/O-bound operations
5. **Use multiprocessing** for CPU-bound operations
6. **Monitor memory usage** and implement periodic cleanup
7. **Set reasonable timeouts** to prevent hanging operations
8. **Implement circuit breakers** for failing RPC endpoints
9. **Use compression** for large data transfers
10. **Profile your application** regularly to identify bottlenecks 