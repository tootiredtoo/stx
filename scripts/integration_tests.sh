#!/bin/bash

# Integration test script for stx file transfer
# This tests the basic functionality of sending and receiving files

set -e

echo "Starting STX file transfer integration test..."

# Create test directories
mkdir -p test_data
mkdir -p test_output

# Generate a 5MB test file
echo "Generating 5MB test file..."
dd if=/dev/urandom of=test_data/test_file.bin bs=1M count=5

# Calculate the original file hash
ORIGINAL_HASH=$(sha256sum test_data/test_file.bin | cut -d' ' -f1)
echo "Original file hash: $ORIGINAL_HASH"

# Start the receiver in the background
echo "Starting stx-recv..."
./stx-recv --listen 12345 --out test_output &
RECV_PID=$!

# Wait a moment for the receiver to start
sleep 2

# Send the file
echo "Sending file with stx-send..."
./stx-send localhost 12345 test_data/test_file.bin 65536

# Wait for file transfer to complete
sleep 2

# Kill the receiver
echo "Stopping stx-recv..."
kill $RECV_PID
wait $RECV_PID 2>/dev/null || true

# Calculate the received file hash
RECEIVED_HASH=$(sha256sum test_output/test_file.bin | cut -d' ' -f1)
echo "Received file hash: $RECEIVED_HASH"

# Compare the hashes
if [ "$ORIGINAL_HASH" == "$RECEIVED_HASH" ]; then
    echo "TEST PASSED: File transferred successfully and hashes match!"
    exit 0
else
    echo "TEST FAILED: File hashes do not match!"
    exit 1
fi