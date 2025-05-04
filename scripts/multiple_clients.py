#!/usr/bin/env python3
"""
STX Multiple Client File Transfer Test - Windows Optimized

This script:
1. Cleans send and receive directories
2. Generates test files with random data of specified size
3. Runs server and multiple clients, with proper Windows process handling
4. Verifies all files were transferred correctly using SHA-256 checksums
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

# Default settings
DEFAULT_PORT = 12345
DEFAULT_FILE_SIZE_MB = 1
DEFAULT_NUM_CLIENTS = 10
RECV_DIR = './recv_files'
SEND_DIR = './send_files'

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
                # Remove directory recursively
                shutil.rmtree(d)
                print(f"Removed directory: {d}")
            except Exception as e:
                print(f"Error removing directory {d}: {e}")
        try:
            # Create directory
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

def kill_process(pid):
    """Force kill a process by PID on Windows."""
    if sys.platform == 'win32':
        # Use taskkill on Windows
        try:
            subprocess.run(['taskkill', '/F', '/PID', str(pid)], 
                           stdout=subprocess.DEVNULL, 
                           stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False
    else:
        # On Unix systems
        try:
            import signal
            os.kill(pid, signal.SIGKILL)
            return True
        except Exception:
            return False

def start_server(port):
    """Start the receiver server process."""
    cmd = ['./build/bin/stx-recv', '--listen', str(port), '--out', RECV_DIR]
    
    # Don't capture output so process doesn't hang on pipe buffer filling
    process = subprocess.Popen(cmd)
    print(f"Started receiver on port {port} with PID {process.pid}")
    return process

def run_client(file_path, port):
    """Run a client process to send a file."""
    cmd = ['./build/bin/stx-send', 'localhost', str(port), file_path]
    
    try:
        # Use subprocess.run with a timeout to prevent hanging
        result = subprocess.run(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True, 
            timeout=60
        )
        
        success = "File sent successfully" in result.stdout
        print(f"File {os.path.basename(file_path)}: {'SUCCESS' if success else 'FAILED'}")
        
        return success
    except subprocess.TimeoutExpired:
        print(f"Timeout sending file {os.path.basename(file_path)}")
        return False

def sequential_transfers(files, port, max_retries=2):
    """Run transfers sequentially with server restarts between failures."""
    results = {}
    
    for file_path in files:
        success = False
        server_process = None
        
        for attempt in range(max_retries + 1):
            # Start a new server for each file
            server_process = start_server(port)
            time.sleep(3)  # Wait for server to initialize
            
            # Run the client
            print(f"Sending {os.path.basename(file_path)} (attempt {attempt+1}/{max_retries+1})...")
            success = run_client(file_path, port)
            
            # Kill the server no matter what
            print(f"Terminating server (PID {server_process.pid})...")
            kill_process(server_process.pid)
            time.sleep(2)  # Wait for port to be released
            
            if success:
                break
            
            if attempt < max_retries:
                print(f"Retrying file {os.path.basename(file_path)}...")
        
        results[file_path] = success
    
    return results

def main():
    parser = argparse.ArgumentParser(description="STX Multiple Client File Transfer Test.")
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to use for transfer')
    parser.add_argument('--size', type=int, default=DEFAULT_FILE_SIZE_MB, help='Size of each test file in MB')
    parser.add_argument('--clients', type=int, default=DEFAULT_NUM_CLIENTS, help='Number of clients to run')
    args = parser.parse_args()
    
    port = args.port
    size_mb = args.size
    num_clients = args.clients
    
    # Clean directories
    clean_directories()
    
    # Generate test files
    generate_test_files(num_clients, size_mb)
    
    # Create list of files to send
    files_to_send = [os.path.join(SEND_DIR, f'file_{i}.bin') for i in range(num_clients)]
    
    # Run sequential transfers (one server per file)
    print(f"Running {num_clients} transfers sequentially with server restart between each...")
    results = sequential_transfers(files_to_send, port)
    
    # Verify file integrity
    print("\nVerifying file integrity...")
    all_success = True
    
    for i in range(num_clients):
        filename = f'file_{i}.bin'
        sent_path = os.path.join(SEND_DIR, filename)
        recv_path = os.path.join(RECV_DIR, filename)
        
        if not os.path.exists(recv_path):
            print(f"ERROR: {filename} was not received")
            all_success = False
            continue
        
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