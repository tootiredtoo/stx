#!/usr/bin/env python3
"""
Basic STX Transfer Test Script

This script:
1. Generates a 5 MB test file with random data
2. Starts stx-recv in the background
3. Runs stx-send to transfer the file
4. Verifies the file was transferred correctly using SHA-256 checksums

Usage:
    python basic_test.py
"""

import os
import sys
import time
import subprocess
import hashlib
import shutil
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
    
    # Determine platform and use appropriate command
    if sys.platform == 'win32':
        # Windows - use PowerShell to create a random file
        size_bytes = size_mb * 1024 * 1024
        block_size = 64 * 1024  # 64 KB blocks
        
        with open(file_path, 'wb') as f:
            remaining = size_bytes
            while remaining > 0:
                chunk_size = min(block_size, remaining)
                f.write(os.urandom(chunk_size))
                remaining -= chunk_size
    else:
        # Linux/macOS - use dd command
        block_size = 1024  # 1 KB blocks
        count = size_mb * 1024
        
        subprocess.run(
            ['dd', 'if=/dev/urandom', f'of={file_path}', 'bs=1K', f'count={count}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True
        )
    
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
    
    # Generate test file
    source_file = TEST_FILE_NAME
    generate_test_file(source_file, size_mb)
    
    # Calculate hash of the source file
    source_hash = calculate_sha256(source_file)
    print(f"Source file SHA-256: {source_hash}")
    
    # Start the receiver in the background
    print(f"Starting stx-recv on port {port}, saving files to {recv_dir}...")
    recv_process = subprocess.Popen(
        ['./build/bin/stx-recv', '--listen', str(port), '--out', recv_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Give the receiver time to start
    time.sleep(2)
    
    try:
        # Run the sender
        print(f"Starting stx-send to transfer {source_file}...")
        sender_result = subprocess.run(
            ['./build/bin/stx-send', 'localhost', str(port), source_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("Sender output:")
        print(sender_result.stdout)
        
        if sender_result.returncode != 0:
            print(f"Error: stx-send failed with code {sender_result.returncode}")
            print("Stderr:", sender_result.stderr)
            sys.exit(1)
        
        # Give the receiver time to finish processing
        time.sleep(2)
        
        # Verify the received file
        received_file = os.path.join(recv_dir, TEST_FILE_NAME)
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
        recv_process.wait(timeout=5)
        
        # Print receiver output
        recv_stdout, recv_stderr = recv_process.communicate()
        if recv_stdout:
            print("Receiver stdout:", recv_stdout.decode())
        if recv_stderr:
            print("Receiver stderr:", recv_stderr.decode())

if __name__ == "__main__":
    main()