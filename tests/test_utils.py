import os
import threading

from web3 import Web3


def generate_random_address():
    random_bytes = os.urandom(32)
    return Web3.keccak(random_bytes).hex()[-40:]


def repeat_in_threads(num_threads, calls_per_thread, func):
    """Run a function without arguments in multiple threads, repeated in each thread.
    Raises an exception if any thread fails (after all threads complete).

    Args:
        num_threads (int): Number of threads to create.
        calls_per_thread (int): How many times to call `func` in each thread.
        func (callable): The function to execute (must take no arguments).

    Raises:
        Exception: If any thread encountered an exception.
    """
    exceptions = []
    lock = threading.Lock()  # Protects shared 'exceptions' list

    def thread_worker():
        try:
            for _ in range(calls_per_thread):
                func()
        except Exception as e:
            with lock:
                exceptions.append(e)

    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=thread_worker)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if exceptions:
        raise Exception(f"{len(exceptions)} threads failed. First error: {exceptions[0]}")
