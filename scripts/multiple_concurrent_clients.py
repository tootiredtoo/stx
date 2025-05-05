#!/usr/bin/env python3
"""
STX Parallel File Transfer Test with Enhanced Retries

This script:
1. Cleans send and receive directories
2. Generates test files with random data of specified size
3. Starts a single server in the background
4. Runs multiple client processes in parallel to send files
5. Implements intelligent retry logic for failed transfers
6. Verifies all files were transferred correctly using SHA-256 checksums
"""

import os
import sys
import time
import subprocess
import hashlib
import argparse
import threading
import shutil
from pathlib import Path
import concurrent.futures
import random

# Default settings
DEFAULT_PORT = 12345
DEFAULT_FILE_SIZE_MB = 1
DEFAULT_NUM_CLIENTS = 10
DEFAULT_MAX_CONCURRENT = 5
DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 5
RECV_DIR = './recv_files'
SEND_DIR = './send_files'
SERVER_START_WAIT = 5  # Seconds to wait for server to initialize

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def clean_directories():
    """Clean send and receive directories before starting."""
    print("Cleaning directories...")
    for d in (RECV_DIR, SEND_DIR):
        if os.path.exists(d):
            try:
                shutil.rmtree(d)
                print(f"Removed directory: {d}")
            except Exception as e:
                print(f"Error removing directory {d}: {e}")
        try:
            os.makedirs(d)
            print(f"Created directory: {d}")
        except Exception as e:
            print(f"Error creating directory {d}: {e}")

def generate_test_files(num_files, size_mb):
    """Generate test files with random data."""
    print(f"Generating {num_files} test files of {size_mb}MB each...")
    for i in range(num_files):
        file_path = os.path.join(SEND_DIR, f'file_{i}.bin')
        size_bytes = size_mb * 1024 * 1024
        
        # Generate random data in chunks
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(file_path, 'wb') as f:
            remaining = size_bytes
            while remaining > 0:
                chunk = min(chunk_size, remaining)
                f.write(os.urandom(chunk))
                remaining -= chunk
        
        print(f"Generated: {file_path} ({size_mb}MB)")

def start_server(port):
    """Start the server process."""
    print(f"Starting server on port {port}...")
    cmd = ['./build/bin/stx-recv', '--listen', str(port), '--out', RECV_DIR]
    
    # Create separate log file for server output
    log_file = open("server_log.txt", "w")
    
    # Start the process
    process = subprocess.Popen(
        cmd,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    print(f"Server started with PID {process.pid}")
    return process, log_file

def kill_server(process, log_file):
    """Kill the server process."""
    if process is None:
        return
    
    print(f"Terminating server (PID: {process.pid})...")
    try:
        if sys.platform == 'win32':
            # On Windows, use taskkill
            subprocess.run(['taskkill', '/F', '/PID', str(process.pid)], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
        else:
            # On Unix
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
    except Exception as e:
        print(f"Error terminating server: {e}")
    
    # Close log file
    if log_file:
        log_file.close()

def print_server_log():
    """Print the server log file contents."""
    try:
        with open("server_log.txt", "r") as f:
            log_content = f.read()
            print("\nServer log:")
            print("===========")
            print(log_content)
            print("===========")
    except Exception as e:
        print(f"Error reading server log: {e}")

def run_client(file_path, port, retry_count=0):
    """Run a client process to send a file."""
    file_name = os.path.basename(file_path)
    retry_suffix = f" (retry {retry_count})" if retry_count > 0 else ""
    print(f"Starting transfer for {file_name}{retry_suffix}...")
    
    cmd = ['./build/bin/stx-send', 'localhost', str(port), file_path]
    
    try:
        # Run with timeout to prevent hanging
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120  # 2 minutes timeout
        )
        
        success = "File sent successfully" in result.stdout
        status = "SUCCESS" if success else "FAILED"
        print(f"Transfer {status} for {file_name}{retry_suffix}")
        
        if not success and retry_count == 0:
            # Print truncated output for debugging only on first failure
            output = result.stdout.strip()
            if len(output) > 500:
                output = output[:500] + "... [truncated]"
            print(f"Client output for {file_name}:\n{output}")
        
        return file_path, success, result.stdout
    except subprocess.TimeoutExpired:
        print(f"Timeout transferring {file_name}{retry_suffix}")
        return file_path, False, "Timeout occurred"

def run_client_with_retries(file_path, port, max_retries, min_delay, max_delay, failed_set):
    """Run a client with intelligent retry backoff."""
    file_name = os.path.basename(file_path)
    
    # First attempt
    file_path, success, output = run_client(file_path, port)
    
    # If successful on the first try, return immediately
    if success:
        return file_path, True, output
    
    # Add to failed set to track concurrent failures
    with failed_set_lock:
        failed_set.add(file_name)
    
    # Retry loop
    retry_count = 0
    while retry_count < max_retries and not success:
        retry_count += 1
        
        # Calculate delay with exponential backoff and jitter
        base_delay = min_delay * (2 ** (retry_count - 1))
        max_calculated_delay = min(base_delay, max_delay)
        actual_delay = random.uniform(min_delay, max_calculated_delay)
        
        # Wait for retry, plus additional time if many failures happening
        with failed_set_lock:
            # If many failures, add more delay proportionally
            if len(failed_set) > 2:
                actual_delay += len(failed_set) * 0.5  # Add 0.5s per failed transfer
        
        print(f"Retry {retry_count}/{max_retries} for {file_name} in {actual_delay:.1f} seconds...")
        time.sleep(actual_delay)
        
        # Retry the transfer
        file_path, success, output = run_client(file_path, port, retry_count)
        
        # If success, remove from failed set
        if success:
            with failed_set_lock:
                if file_name in failed_set:
                    failed_set.remove(file_name)
    
    # Final outcome
    if not success:
        print(f"All {max_retries} retries failed for {file_name}")
    
    return file_path, success, output

def main():
    parser = argparse.ArgumentParser(description="STX Parallel File Transfer Test")
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to use for transfer')
    parser.add_argument('--size', type=int, default=DEFAULT_FILE_SIZE_MB, help='Size of each test file in MB')
    parser.add_argument('--clients', type=int, default=DEFAULT_NUM_CLIENTS, help='Number of clients to run')
    parser.add_argument('--max-concurrent', type=int, default=DEFAULT_MAX_CONCURRENT, 
                        help='Maximum number of concurrent clients')
    parser.add_argument('--retries', type=int, default=DEFAULT_RETRIES,
                        help='Maximum number of retries for failed transfers')
    parser.add_argument('--min-delay', type=float, default=1.0,
                        help='Minimum retry delay in seconds')
    parser.add_argument('--max-delay', type=float, default=15.0,
                        help='Maximum retry delay in seconds')
    args = parser.parse_args()
    
    port = args.port
    size_mb = args.size
    num_clients = args.clients
    max_concurrent = args.max_concurrent
    max_retries = args.retries
    min_delay = args.min_delay
    max_delay = args.max_delay
    
    # Clean directories
    clean_directories()
    
    # Generate test files
    generate_test_files(num_clients, size_mb)
    
    # Start server
    server_process, log_file = start_server(port)
    
    # Wait for server to initialize
    print(f"Waiting {SERVER_START_WAIT} seconds for server to initialize...")
    time.sleep(SERVER_START_WAIT)
    
    # Check if server is still running
    if server_process.poll() is not None:
        print(f"Error: Server exited prematurely with code {server_process.returncode}")
        kill_server(server_process, log_file)
        print_server_log()
        return 1
    
    # Create list of files to send
    files_to_send = [os.path.join(SEND_DIR, f'file_{i}.bin') for i in range(num_clients)]
    
    # Track set of currently failing files (for coordinating backoff)
    global failed_set_lock
    failed_set_lock = threading.Lock()
    failed_set = set()
    
    # Run clients in parallel with a thread pool
    results = {}
    try:
        print(f"Running {num_clients} clients in parallel (max {max_concurrent} at a time)...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(
                    run_client_with_retries, 
                    file_path, 
                    port,
                    max_retries,
                    min_delay,
                    max_delay,
                    failed_set
                ): file_path for file_path in files_to_send
            }
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_file):
                file_path, success, _ = future.result()
                results[file_path] = success
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    finally:
        # Kill server
        kill_server(server_process, log_file)
        print_server_log()
    
    # Verify file integrity
    print("\nVerifying file integrity...")
    all_success = True
    
    for i in range(num_clients):
        filename = f'file_{i}.bin'
        sent_path = os.path.join(SEND_DIR, filename)
        recv_path = os.path.join(RECV_DIR, filename)
        
        # Skip files that weren't successfully sent according to the client
        if sent_path in results and not results[sent_path]:
            print(f"SKIP: {filename} (client reported failure)")
            all_success = False
            continue
        
        if not os.path.exists(recv_path):
            print(f"ERROR: {filename} was not received")
            all_success = False
            continue
        
        # Compare file sizes
        sent_size = os.path.getsize(sent_path)
        recv_size = os.path.getsize(recv_path)
        if sent_size != recv_size:
            print(f"ERROR: Size mismatch for {filename}. Sent: {sent_size}, Received: {recv_size}")
            all_success = False
            continue
        
        # Compare hashes
        sent_hash = calculate_sha256(sent_path)
        recv_hash = calculate_sha256(recv_path)
        
        if sent_hash == recv_hash:
            print(f"OK: {filename} verified ({size_mb}MB)")
        else:
            print(f"ERROR: Hash mismatch for {filename}")
            all_success = False
    
    # Summary
    print("\nSummary:")
    for file_path, success in results.items():
        status = "SUCCESS" if success else "FAILED"
        print(f"{os.path.basename(file_path)}: {status}")
    
    if all_success:
        print("\nAll files transferred and verified successfully!")
        return 0
    else:
        print("\nSome files failed to transfer correctly")
        return 1

if __name__ == "__main__":
    sys.exit(main())