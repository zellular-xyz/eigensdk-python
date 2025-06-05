import threading
import time
from web3 import Web3
from tests.builder import clients_array, config


def metadata_worker(client, thread_id, num_updates=100):
    """
    Worker function that performs multiple metadata URI updates using the given client.
    
    Args:
        client: The client object containing el_writer
        thread_id: Identifier for this thread
        num_updates: Number of metadata updates to perform
    """
    operator_addr = config[f"operator_address_{thread_id}"]
    
    successful_updates = 0
    failed_updates = 0
    
    print(f"Thread {thread_id} starting {num_updates} metadata updates...")
    
    for i in range(num_updates):
        try:
            # Generate unique metadata URI for each update
            metadata_uri = f"https://example.com/updated-metadata-uri-thread-{thread_id}-update-{i+1}"
            receipt = client.el_writer.update_metadata_uri(operator_addr, metadata_uri)
            
            if receipt is not None and receipt["status"] == 1:
                successful_updates += 1
                if (i + 1) % 10 == 0:  # Print progress every 10 updates
                    print(f"Thread {thread_id}: Completed {i + 1}/{num_updates} metadata updates")
            else:
                failed_updates += 1
                print(f"Thread {thread_id}: Metadata update {i + 1} failed - invalid receipt")
                
        except Exception as e:
            failed_updates += 1
            print(f"Thread {thread_id}: Metadata update {i + 1} failed with error: {str(e)}")
    
    print(f"Thread {thread_id} completed: {successful_updates} successful, {failed_updates} failed metadata updates")
    return successful_updates, failed_updates


def test_threaded_metadata_updates():
    """
    Test that performs 100 metadata URI updates across 3 threads using different clients.
    Each thread uses a different client from clients_array.
    """
    num_threads = 3
    updates_per_thread = 100
    
    print(f"Starting threaded metadata update test with {num_threads} threads, {updates_per_thread} updates each...")
    
    # Ensure we have 3 clients available
    assert len(clients_array) >= num_threads, f"Need at least {num_threads} clients, got {len(clients_array)}"
    
    threads = []
    results = {}
    
    start_time = time.time()
    
    # Create and start threads
    for i in range(num_threads):
        thread = threading.Thread(
            target=lambda client=clients_array[i], tid=i+1: 
                results.update({tid: metadata_worker(client, tid, updates_per_thread)}),
            name=f"MetadataThread-{i+1}"
        )
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Collect and verify results
    total_successful = 0
    total_failed = 0
    
    for thread_id in range(1, num_threads + 1):
        if thread_id in results:
            successful, failed = results[thread_id]
            total_successful += successful
            total_failed += failed
        else:
            print(f"Warning: No results found for thread {thread_id}")
    
    print(f"\n=== Test Results ===")
    print(f"Total execution time: {total_time:.2f} seconds")
    print(f"Total successful metadata updates: {total_successful}")
    print(f"Total failed metadata updates: {total_failed}")
    print(f"Expected total updates: {num_threads * updates_per_thread}")
    print(f"Success rate: {(total_successful / (num_threads * updates_per_thread)) * 100:.2f}%")
    
    # Assert that we have a reasonable success rate (at least 90%)
    expected_total = num_threads * updates_per_thread
    success_rate = total_successful / expected_total
    
    assert success_rate >= 0.9, f"Success rate too low: {success_rate:.2%}. Expected at least 90%"
    assert total_successful + total_failed == expected_total, "Total updates don't match expected count"
    
    print("✅ Threaded metadata update test completed successfully!")


if __name__ == "__main__":
    test_threaded_metadata_updates()
