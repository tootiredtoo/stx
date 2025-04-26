On Linux/macOS: 
1. Make generate_keys.sh script executable and run it: 
chmod +x scripts/generate_keys.sh && scripts/generate_keys.sh
2. Make generate_data.sh script executable and run it: 
chmod +x scripts/generate_data.sh && scripts/generate_data.sh

On Windows: 
1. Run the generate_keys.bat script:
scripts/generate_keys.bat
2. Run the generate_data.bat script:
scripts/generate_data.bat

----- ! FOR TEST PURPOSES ! -----

For running stx-server:

On Linux/macOS: 
1. Make generate_debug_keys.sh script executable and run it: 
chmod +x scripts/generate_debug_keys.sh && scripts/generate_debug_keys.sh
2. Build and run application:

On Windows: 
1. Run the generate_debug_keys.bat script:
scripts/generate_debug_keys.bat
2. Build and run application:
mkdir build && cd build && cmake .. && make && build/stx-server.exe
3. In the different terminal run the client:
openssl s_client -connect 127.0.0.1:443 -CAfile certs/server.crt
4. In the client's terminal write someting (optionally) and press Enter. 



# STX - Secure TCP Transfer

STX is a set of command-line utilities for securely transferring files over TCP with end-to-end encryption, authentication, and resume capability.

## Features

- End-to-end encryption using AES-256-GCM
- Mutual authentication using pre-shared keys
- Transfer resume capability after connection interruptions
- File integrity verification with CRC32 checksums
- Support for multiple simultaneous client connections

## Building from Source

### Prerequisites

- C++11 compatible compiler
- CMake (version 3.20 or higher)
- OpenSSL development libraries

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/tootiredtoo/stx.git
cd stx

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make

# Run tests (optional)
make test
```

## Usage

### Setting up a Shared Key

STX uses a pre-shared key for authentication and encryption. You can set it in one of two ways:

1. Environment variable:
   ```bash
   export STX_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
   ```

2. Key file:
   ```bash
   echo -n "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" > /path/to/key
   export STX_KEY_FILE="/path/to/key"
   ```

### Receiving Files

To receive files, use the `stx-recv` utility:

```bash
./stx-recv --listen 12345 --out /path/to/download/directory
```

This will start listening on port 12345 and save received files to the specified directory.

### Sending Files

To send a file to a receiver, use the `stx-send` utility:

```bash
./stx-send <hostname> <port> /path/to/file.bin [block_size]
```

For example:

```bash
./stx-send localhost 12345 document.pdf 65536
```

This sends the file "document.pdf" to a receiver running on the local machine at port 12345, using a block size of 64KB.

## Integration Testing

STX includes integration test scripts to verify that file transfers work correctly:

```bash
# Basic transfer test
./test_transfer.sh

# Resume capability test
./test_resume.sh
```

## Error Codes

STX utilities use the following exit codes:

- 0: Success
- 1: Network error
- 2: Authentication error
- 3: I/O error
- 4: Encryption error
- 5: Protocol error