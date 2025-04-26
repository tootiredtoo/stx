#!/usr/bin/env python3
"""
Advanced STX Transfer Test Script with Disconnection Simulation

This script:
1. Generates a 5 MB test file with random data
2. Starts stx-recv in the background
3. Runs stx-send to transfer the file
4. Interrupts the transfer by killing the sender process
5. Restarts the sender to resume the transfer
6. Verifies the file was transferred correctly using SHA-256 checksums

Usage:
    python disconnect_test.py
"""

import os
import sys
import time
import subprocess
import hashlib
import shutil
import signal
import argparse
import random
from pathlib import Path

# Default settings
DEFAULT_PORT = 12345
DEFAULT_FILE_SIZE_MB = 5
TEST_FILE_NAME = "test_data.bin"
DEFAULT_INTERRUPTIONS = 2
DEFAULT_MIN_WAIT_SEC = 1
DEFAULT_MAX_WAIT_SEC = 3

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

def run_sender_with_interruptions(source_file, port, num_interruptions, min_wait_sec, max_wait_sec):
    """Run the sender with simulated interruptions."""
    for i in range(num_interruptions + 1):
        print(f"Starting stx-send attempt {i+1} of {num_interruptions+1}...")
        
        # Start the sender
        sender_process = subprocess.Popen(
            ['./build/bin/stx-send', 'localhost', str(port), source_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        if i < num_interruptions:
            # Wait for a random amount of time before interrupting
            wait_time = random.uniform(min_wait_sec, max_wait_sec)
            print(f"Will interrupt after {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            
            # Interrupt the transfer
            print("Interrupting transfer...")
            if sys.platform == 'win32':
                # Windows
                sender_process.terminate()
            else:
                # Linux/macOS
                sender_process.send_signal(signal.SIGINT)
            
            # Wait for the process to exit
            sender_process.wait(timeout=5)
            
            # Print process output
            stdout, stderr = sender_process.communicate()
            if stdout:
                print("Sender stdout:", stdout.decode())
            if stderr:
                print("Sender stderr:", stderr.decode())
            
            # Wait before trying again
            time.sleep(1)
        else:
            # Last attempt - wait for completion
            sender_process.wait()
            stdout, stderr = sender_process.communicate()
            
            print("Final sender output:")
            if stdout:
                print(stdout.decode())
            
            if sender_process.returncode != 0:
                print(f"Error: Final sender process failed with code {sender_process.returncode}")
                if stderr:
                    print("Stderr:", stderr.decode())
                return False
    
    return True

def main():
    parser = argparse.ArgumentParser(description='Test STX file transfer with disconnections.')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port to use for transfer')
    parser.add_argument('--size', type=int, default=DEFAULT_FILE_SIZE_MB, help='Size of test file in MB')
    parser.add_argument('--recv-dir', default='./recv_files', help='Directory to store received files')
    parser.add_argument('--interruptions', type=int, default=DEFAULT_INTERRUPTIONS, 
                        help='Number of times to interrupt the transfer')
    parser.add_argument('--min-wait', type=float, default=DEFAULT_MIN_WAIT_SEC,
                        help='Minimum time to wait before interrupting (seconds)')
    parser.add_argument('--max-wait', type=float, default=DEFAULT_MAX_WAIT_SEC,
                        help='Maximum time to wait before interrupting (seconds)')
    args = parser.parse_args()
    
    port = args.port
    size_mb = args.size
    recv_dir = args.recv_dir
    num_interruptions = args.interruptions
    min_wait_sec = args.min_wait
    max_wait_sec = args.max_wait
    
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
        # Run the sender with interruptions
        success = run_sender_with_interruptions(
            source_file, port, num_interruptions, min_wait_sec, max_wait_sec
        )
        
        if not success:
            print("ERROR: File transfer failed.")
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