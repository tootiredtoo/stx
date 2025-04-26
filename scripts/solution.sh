#!/bin/bash

# Generate 5 MB of random data and save it as test_file.dat
dd if=/dev/urandom of=test_file.dat bs=1M count=5

# Start stx-recv in the background to listen for the file on a specified port
# (using port 12345 as an example)
./stx-recv --port 12345 &

# Wait a moment for stx-recv to be ready
sleep 2

# Start stx-send to send the generated test_file.dat
./stx-send --file test_file.dat --port 12345

# Wait for the stx-recv to finish receiving the file
wait

# Verify the file using sha256sum and save the file if it is authentic
echo "Comparing files using sha256sum..."
sha256sum test_file.dat received_file.dat > sha256_output.txt

# Check if the hashes match
if grep -q "OK" sha256_output.txt; then
    echo "File is authentic. Saving the received file."
else
    echo "File is not authentic. Transfer failed."
    exit 1
fi
