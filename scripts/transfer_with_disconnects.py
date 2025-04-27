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
    python solution_disconnects.py
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
import threading
import glob
from pathlib import Path

# Default settings
DEFAULT_PORT = 12345
DEFAULT_FILE_SIZE_MB = 10
TEST_FILE_NAME = "test_data.bin"
DEFAULT_INTERRUPTIONS = 8
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

def run_process_with_timeout(cmd, timeout=60):
    """Run a process with timeout and return its output."""
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    stdout_data = []
    stderr_data = []
    
    def read_output(pipe, data_list):
        for line in iter(pipe.readline, ''):
            data_list.append(line)
            print(line, end='')  # Print output in real-time
    
    # Start threads to read stdout and stderr
    stdout_thread = threading.Thread(target=read_output, args=(process.stdout, stdout_data))
    stderr_thread = threading.Thread(target=read_output, args=(process.stderr, stderr_data))
    stdout_thread.daemon = True
    stderr_thread.daemon = True
    stdout_thread.start()
    stderr_thread.start()
    
    # Wait for the process to complete or timeout
    try:
        returncode = process.wait(timeout=timeout)
        # Wait a bit longer for threads to finish reading output
        stdout_thread.join(1)
        stderr_thread.join(1)
        return returncode, ''.join(stdout_data), ''.join(stderr_data)
    except subprocess.TimeoutExpired:
        process.kill()
        return None, ''.join(stdout_data), ''.join(stderr_data)

def run_sender_with_interruptions(source_file, port, num_interruptions, min_wait_sec, max_wait_sec):
    """Run the sender with simulated interruptions."""
    sender_cmd = ['./build/bin/stx-send', 'localhost', str(port), source_file]
    
    for i in range(num_interruptions + 1):
        print(f"\n==== Starting stx-send attempt {i+1} of {num_interruptions+1} ====")
        
        if i < num_interruptions:
            # For interruptions, start the sender in a subprocess we can kill
            sender_process = subprocess.Popen(
                sender_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for a random amount of time before interrupting
            wait_time = random.uniform(min_wait_sec, max_wait_sec)
            print(f"Will interrupt after {wait_time:.2f} seconds...")
            time.sleep(wait_time)
            
            # Interrupt the transfer
            print("Interrupting transfer...")
            if sys.platform == 'win32':
                sender_process.terminate()
            else:
                sender_process.send_signal(signal.SIGINT)
            
            try:
                stdout, stderr = sender_process.communicate(timeout=5)
                if stdout:
                    print(f"Interrupted stdout: {stdout.decode()}")
                if stderr:
                    print(f"Interrupted stderr: {stderr.decode()}")
            except subprocess.TimeoutExpired:
                print("Warning: Sender not responding to interrupt, killing...")
                sender_process.kill()
                stdout, stderr = sender_process.communicate()
            
            # Wait before trying again
            time.sleep(1)
        else:
            # For the final attempt, use our timeout function
            print("Starting final transfer attempt...")
            print(f"Running command: {' '.join(sender_cmd)}")
            
            returncode, stdout, stderr = run_process_with_timeout(sender_cmd, timeout=120)
            
            if returncode is None:
                print("ERROR: Final transfer timed out after 120 seconds")
                return False
            
            if returncode != 0:
                print(f"ERROR: Final transfer failed with return code {returncode}")
                print(f"stderr: {stderr}")
                return False
            
            print("Final transfer completed successfully")
    
    return True

def find_latest_file(directory, base_name=None):
    """Find the most recently created file in the directory, optionally matching base name."""
    pattern = os.path.join(directory, f"{base_name}*" if base_name else "*")
    files = glob.glob(pattern)
    if not files:
        return None
    
    # Get the most recently created file
    latest_file = max(files, key=os.path.getctime)
    print(f"Found latest file: {latest_file}")
    return latest_file

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
    
    # Clear any previous received files that might confuse our test
    for old_file in glob.glob(os.path.join(recv_dir, f"{TEST_FILE_NAME}*")):
        print(f"Removing old file: {old_file}")
        os.remove(old_file)
    
    # Start the receiver in the background with real-time output processing
    recv_cmd = ['./build/bin/stx-recv', '--listen', str(port), '--out', recv_dir]
    print(f"Starting receiver: {' '.join(recv_cmd)}")
    
    recv_process = subprocess.Popen(
        recv_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    # Set up threads to read receiver output in real time
    def print_output(pipe, prefix):
        for line in iter(pipe.readline, ''):
            print(f"{prefix}: {line}", end='')
    
    recv_stdout_thread = threading.Thread(target=print_output, args=(recv_process.stdout, "RECV"))
    recv_stderr_thread = threading.Thread(target=print_output, args=(recv_process.stderr, "RECV ERR"))
    recv_stdout_thread.daemon = True
    recv_stderr_thread.daemon = True
    recv_stdout_thread.start()
    recv_stderr_thread.start()
    
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
        
        # Find the latest received file that matches our test file name
        received_file = find_latest_file(recv_dir, TEST_FILE_NAME)
        
        if received_file and os.path.exists(received_file):
            received_hash = calculate_sha256(received_file)
            print(f"Received file SHA-256: {received_hash}")
            
            if source_hash == received_hash:
                print("SUCCESS: Files match!")
            else:
                print("ERROR: Files do not match!")
                
                # Show file sizes for debugging
                source_size = os.path.getsize(source_file)
                received_size = os.path.getsize(received_file)
                print(f"Source file size: {source_size} bytes")
                print(f"Received file size: {received_size} bytes")
                
                # Compare the first few bytes
                with open(source_file, 'rb') as f1, open(received_file, 'rb') as f2:
                    source_start = f1.read(100)
                    received_start = f2.read(100)
                    if source_start != received_start:
                        print("First bytes differ!")
                
                sys.exit(1)
        else:
            print(f"ERROR: Received file not found in {recv_dir}")
            print("Files in directory:")
            for f in os.listdir(recv_dir):
                print(f"  {f}")
            sys.exit(1)
    
    finally:
        # Terminate the receiver
        print("Terminating receiver...")
        if sys.platform == 'win32':
            recv_process.terminate()
        else:
            recv_process.send_signal(signal.SIGINT)
        
        # Give it a chance to exit gracefully
        try:
            recv_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Warning: Receiver not responding, killing...")
            recv_process.kill()
            recv_process.wait()

if __name__ == "__main__":
    main()