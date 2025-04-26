#!/bin/bash

# File to store the generated data
output_file="test_file.dat"

# Generate 5MB of random data using dd
dd if=/dev/urandom of=$output_file bs=1M count=5 status=progress

echo "5MB file created: $output_file"
