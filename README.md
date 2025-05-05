# STX - Secure TCP Transfer

STX is a set of command-line utilities for securely transferring files over TCP with end-to-end encryption, authentication, and resume capability.

## Features

- End-to-end encryption using AES-256-GCM
- Mutual authentication using pre-shared keys
- Transfer resume capability after connection interruptions
- File integrity verification with CRC32 checksums
- Support for multiple simultaneous client connections

## Building from Source

### Compiler and Tools

- C++ Compiler: MinGW GCC (g++) 
- C Compiler: MinGW GCC (gcc) 
- Build System: CMake (version >= 3.20)
- Generator: MinGW Makefiles

### Build Targets

- stx-core (core library)
- stx-send (sender executable)
- stx-recv (receiver executable)

### Test targets

- crypto_tests
- protocol_client_tests
- protocol_messages_tests
- protocol_server_tests

### Prerequisites and dependencies

- C++11 compatible compiler
- CMake (version 3.20 or higher)
- OpenSSL development libraries
- Google Test (gtest, gtest_main, gmock, gmock_main) is being used for testing
- The project pulls in dependencies using CMake's FetchContent (as seen in the CMakeLists.txt)

### Build Instructions

#### Install Prerequisites

- CMake 3.20 or higher
- MinGW-w64 with GCC/G++ (MSYS2 package)
- OpenSSL development libraries (required by the project)

```bash
# Clone the repository
git clone https://github.com/tootiredtoo/stx.git
cd stx

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
make
```

The compiled executables will be located in build/bin/ directory.

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

### Basic transfer test

#### Purpose

Tests the STX file transfer functionality by generating random test files, transferring them, and verifying the integrity of the transfer.

#### Description

This script generates the specified number of random test files, starts the STX receiver, transfers the files simultaneously using multiple threads, and then verifies the transfer by comparing file hashes.

#### Usage

```python
py ./scripts/one_file_transfer.py [--port PORT] [--size SIZE] [--clients NUM_CLIENTS]
```

#### Parameters
```python
--port: Port to use for the transfer (default: 12345)
--size: Size of each test file in MB (default: 1)
--clients: Number of clients to run (default: 10)
```
### Transfer_with_disconnects

#### Purpose

Tests the resume capability of STX by simulating network disconnections during file transfers.

#### Description

This advanced test script generates a test file, then deliberately interrupts the transfer multiple times by killing the sender process. It then restarts the sender to continue the transfer, testing STX's ability to resume incomplete transfers. After all interruptions, it verifies the file integrity to ensure the resume functionality works correctly.
The script reports detailed information about the transfer, including the timing of interruptions, how much of the file was transferred between interruptions, and confirmation that the final file matches the source file.

#### Usage

```python
python transfer_with_disconnects.py [--port PORT] [--size SIZE] [--recv-dir RECV_DIR] [--interruptions NUM_INTERRUPTIONS] [--min-wait MIN_WAIT] [--max-wait MAX_WAIT]
```

#### Parameters
```python
--port: Port to use for the transfer (default: 12345)
--size: Size of test file in MB (default: 10)
--recv-dir: Directory to store received files (default: ./recv_files)
--interruptions: Number of times to interrupt the transfer (default: 8)
--min-wait: Minimum time to wait before interrupting (seconds) (default: 1)
--max-wait: Maximum time to wait before interrupting (seconds) (default: 3)
```
### Sequential file transfer with multiple clients

#### Purpose

Tests the STX file transfer system with sequential file transfers, ensuring reliability by running one transfer at a time with server restarts between files.

#### Description

Unlike the concurrent version, this script processes one file at a time sequentially. For each file, it starts a fresh server instance, transfers the file, validates the result, then terminates the server before moving to the next file. This approach eliminates concurrency issues completely, making it useful for baseline testing or for environments where the server has limited resources. The script includes retry logic for failed transfers and comprehensive reporting on the success or failure of each file transfer.
These scripts complement the existing test suite by providing both high-concurrency testing (multiple_concurrent_clients.py) and highly reliable sequential testing (multiple_sequential_clients.py), helping to validate different aspects of the STX secure file transfer protocol's performance and reliability.

#### Usage

```python
python multiple_sequential_clients.py [--port PORT] [--size SIZE] [--clients NUM_CLIENTS] [--retries MAX_RETRIES]
```

#### Parameters
```python
--port: Port to use for the transfer (default: 12345)
--size: Size of each test file in MB (default: 1)
--clients: Number of clients/files to process (default: 3)
--retries: Maximum number of retries per file (default: 2)
```
### Concurrent file transfer with multiple clients

#### Purpose

Tests the STX file transfer system with parallel file transfers, allowing multiple clients to send files simultaneously while monitoring success rates and implementing retry logic.

#### Description

This script tests the STX server's ability to handle multiple concurrent file transfers. It generates random test files, starts a single STX server, then uses ThreadPoolExecutor to manage multiple concurrent client connections. The script includes intelligent retry logic with exponential backoff and jitter to handle failed transfers. After all transfers complete or fail, it verifies the integrity of the transferred files using SHA-256 checksums.

#### Usage

```python
python multiple_concurrent_clients.py [--port PORT] [--size SIZE] [--clients NUM_CLIENTS] [--max-concurrent MAX_CONCURRENT] [--retries MAX_RETRIES] [--min-delay MIN_DELAY] [--max-delay MAX_DELAY]
```

#### Parameters
```python
--port: Port to use for the transfer (default: 12345)
--size: Size of each test file in MB (default: 1)
--clients: Number of clients/files to run (default: 3)
--max-concurrent: Maximum number of concurrent transfers (default: 2)
--retries: Maximum number of retries for failed transfers (default: 3)
--min-delay: Minimum retry delay in seconds (default: 1.0)
--max-delay: Maximum retry delay in seconds (default: 15.0)
```
## Error Codes

STX utilities use the following exit codes:

- 0: Success
- 1: Network error
- 2: Authentication error
- 3: I/O error
- 4: Encryption error
- 5: Protocol error