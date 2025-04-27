#!/usr/bin/env python3
"""
Simple STX Transfer Test Script

This script:
1. Generates a test file with random data
2. Starts stx-recv in the background
3. Runs stx-send to transfer the file
4. Verifies the file was transferred correctly

Usage:
    python simple_transfer.py
"""

import os
import sys
import time
import subprocess
import hashlib
import signal
import argparse
from pathlib import Path

# Default settings
DEFAULT_PORT = 12345
DEFAULT_FILE_SIZE_MB = 5
TEST_FILE_NAME = "test_data.bin"

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def generate_test_file(file_path, size_mb):
    """Generate a test file with random data."""
    print(f"Generating {size_mb} MB test file at {file_path}...")
    
    size_bytes = size_mb * 1024 * 1024
    block_size = 64 * 1024  # 64 KB blocks
    
    with open(file_path, 'wb') as f:
        remaining = size_bytes
        while remaining > 0:
            chunk_size = min(block_size, remaining)
            f.write(os.urandom(chunk_size))
            remaining -= chunk_size
    
    print(f"Test file generated: {file_path}")

def main():
    parser = argparse.ArgumentParser(description='Test STX file transfer.')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to use for transfer')
    parser.add_argument('--size', type=int, default=DEFAULT_FILE_SIZE_MB, help='Size of test file in MB')
    parser.add_argument('--recv-dir', default='./recv_files', help='Directory to store received files')
    args = parser.parse_args()
    
    port = args.port
    size_mb = args.size
    recv_dir = args.recv_dir
    
    # Create the receive directory if it doesn't exist
    os.makedirs(recv_dir, exist_ok=True)
    
    # Delete existing test files to avoid conflicts
    received_file = os.path.join(recv_dir, TEST_FILE_NAME)
    if os.path.exists(received_file):
        os.remove(received_file)
    
    # Generate test file
    source_file = TEST_FILE_NAME
    generate_test_file(source_file, size_mb)
    
    # Calculate hash of the source file
    source_hash = calculate_sha256(source_file)
    print(f"Source file SHA-256: {source_hash}")
    
    # Start the receiver in the background
    print(f"Starting stx-recv on port {port}, saving files to {recv_dir}...")
    recv_cmd = ['./build/bin/stx-recv', '--listen', str(port), '--out', recv_dir]
    
    with open('recv_output.log', 'w') as recv_log:
        recv_process = subprocess.Popen(
            recv_cmd,
            stdout=recv_log,
            stderr=subprocess.STDOUT,
            text=True
        )
    
    # Give the receiver time to start
    time.sleep(3)
    
    try:
        # Run the sender
        print(f"Starting stx-send to transfer {source_file}...")
        sender_cmd = ['./build/bin/stx-send', 'localhost', str(port), source_file]
        
        with open('send_output.log', 'w') as send_log:
            sender_result = subprocess.run(
                sender_cmd,
                stdout=send_log,
                stderr=subprocess.STDOUT,
                text=True
            )
        
        # Print sender output
        with open('send_output.log', 'r') as send_log:
            print("\n--- Sender Output ---")
            print(send_log.read())
        
        if sender_result.returncode != 0:
            print(f"Error: stx-send failed with code {sender_result.returncode}")
            # Print receiver output for debugging
            with open('recv_output.log', 'r') as recv_log:
                print("\n--- Receiver Output ---")
                print(recv_log.read())
            sys.exit(1)
        
        # Give the receiver time to finish processing
        time.sleep(3)
        
        # Verify the received file
        if os.path.exists(received_file):
            received_hash = calculate_sha256(received_file)
            print(f"Received file SHA-256: {received_hash}")
            
            if source_hash == received_hash:
                print("SUCCESS: Files match!")
            else:
                print("ERROR: Files do not match!")
                sys.exit(1)
        else:
            print(f"ERROR: Received file not found at {received_file}")
            with open('recv_output.log', 'r') as recv_log:
                print("\n--- Receiver Output ---")
                print(recv_log.read())
            sys.exit(1)
    
    finally:
        # Terminate the receiver
        print("Terminating receiver...")
        if sys.platform == 'win32':
            # Windows
            recv_process.terminate()
        else:
            # Linux/macOS
            recv_process.send_signal(signal.SIGINT)
        
        # Wait for the receiver to exit
        try:
            recv_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Warning: Receiver not responding, killing...")
            recv_process.kill()
            recv_process.wait()
        
        # Print receiver output
        with open('recv_output.log', 'r') as recv_log:
            print("\n--- Receiver Output ---")
            print(recv_log.read())

if __name__ == "__main__":
    main()