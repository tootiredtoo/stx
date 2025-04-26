#!/bin/bash

# Resume test script for stx file transfer
# This tests the resume functionality when a transfer is interrupted

set -e

echo "Starting STX resume functionality test..."

# Create test directories
mkdir -p test_data
mkdir -p test_output

# Generate a 10MB test file
echo "Generating 10MB test file..."
dd if=/dev/urandom of=test_data/resume_test.bin bs=1M count=10

# Calculate the original file hash
ORIGINAL_HASH=$(sha256sum test_data/resume_test.bin | cut -d' ' -f1)
echo "Original file hash: $ORIGINAL_HASH"

# Start the receiver in the background
echo "Starting stx-recv (first instance)..."
./stx-recv --listen 12346 --out test_output &
RECV_PID=$!

# Wait a moment for the receiver to start
sleep 2

# Start sending the file but interrupt after a short time
echo "Starting initial file transfer..."
timeout 2s ./stx-send localhost 12346 test_data/resume_test.bin 65536 || true

# Kill the first receiver
echo "Stopping first stx-recv instance..."
kill $RECV_PID
wait $RECV_PID 2>/dev/null || true

# Wait a moment
sleep 2

# Start the receiver again for resume
echo "Starting stx-recv (second instance)..."
./stx-recv --listen 12346 --out test_output &
RECV_PID=$!

# Wait a moment for the receiver to start
sleep 2

# Send the file again (should resume)
echo "Resuming file transfer..."
./stx-send localhost 12346 test_data/resume_test.bin 65536

# Wait for file transfer to complete
sleep 2

# Kill the receiver
echo "Stopping second stx-recv instance..."
kill $RECV_PID
wait $RECV_PID 2>/dev/null || true

# Calculate the received file hash
RECEIVED_HASH=$(sha256sum test_output/resume_test.bin | cut -d' ' -f1)
echo "Received file hash: $RECEIVED_HASH"

# Compare the hashes
if [ "$ORIGINAL_HASH" == "$RECEIVED_HASH" ]; then
    echo "TEST PASSED: File resumed and transferred successfully, hashes match!"
    exit 0
else
    echo "TEST FAILED: File hashes do not match after resume!"
    exit 1
fi