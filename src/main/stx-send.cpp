#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include "crypto/crypto.hpp"
#include "protocols/protocol.hpp"


// Default block size (64KB)
constexpr uint32_t DEFAULT_BLOCK_SIZE = 65536;

// Maximum retries for connection
constexpr int MAX_RETRIES = 5;

// Retry delay in milliseconds
constexpr int RETRY_DELAY_MS = 1000;

void print_usage(const char* program_name) {
  std::cerr << "Usage: " << program_name << " <host> <port> <file_path> [block_size]" << std::endl;
  std::cerr << "  host      - Hostname or IP address of the receiver" << std::endl;
  std::cerr << "  port      - Port number of the receiver" << std::endl;
  std::cerr << "  file_path - Path to the file to send" << std::endl;
  std::cerr << "  block_size - Optional: Size of blocks for transfer (default: "
            << DEFAULT_BLOCK_SIZE << " bytes)" << std::endl;
}

int main(int argc, char* argv[]) {
  // Initialize OpenSSL
  if (!stx::crypto::initialize()) {
    std::cerr << "Error: Failed to initialize OpenSSL" << std::endl;
    return 1;
  }

  // Parse command line arguments
  if (argc < 4) {
    print_usage(argv[0]);
    return 1;
  }

  const std::string host = argv[1];
  const uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
  const std::string file_path = argv[3];

  uint32_t block_size = DEFAULT_BLOCK_SIZE;
  if (argc > 4) {
    block_size = static_cast<uint32_t>(std::stoul(argv[4]));
  }

  // Check if the file exists and is readable
  if (!std::filesystem::exists(file_path)) {
    std::cerr << "Error: File does not exist: " << file_path << std::endl;
    return 3;  // I/O error
  }

  // Get file size
  std::uintmax_t file_size = std::filesystem::file_size(file_path);

  std::cout << "Sending file: " << file_path << std::endl;
  std::cout << "File size: " << file_size << " bytes" << std::endl;
  std::cout << "Block size: " << block_size << " bytes" << std::endl;

  // Try to create client session with retries
  std::unique_ptr<stx::protocol::ClientSession> session = nullptr;
  int retry_count = 0;

  while (!session && retry_count < MAX_RETRIES) {
    try {
      std::cout << "Connecting to " << host << ":" << port << "..." << std::endl;
      session = stx::protocol::create_client_session(host, port);

      if (!session) {
        retry_count++;
        if (retry_count < MAX_RETRIES) {
          std::cerr << "Connection attempt " << retry_count << " failed. Retrying in "
                    << RETRY_DELAY_MS << "ms..." << std::endl;
          std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
        }
      }
    } catch (const std::exception& e) {
      std::cerr << "Connection error: " << e.what() << std::endl;
      retry_count++;
      if (retry_count < MAX_RETRIES) {
        std::cerr << "Connection attempt " << retry_count << " failed. Retrying in "
                  << RETRY_DELAY_MS << "ms..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_DELAY_MS));
      }
    }
  }

  if (!session) {
    std::cerr << "Error: Failed to connect after " << MAX_RETRIES << " attempts" << std::endl;
    return 1;  // Network error
  }

  // Perform the handshake
  std::cout << "Performing handshake..." << std::endl;
  if (!session->client_handshake()) {
    std::cerr << "Error: Handshake failed" << std::endl;
    session->close();
    return 2;  // Authentication error
  }
  std::cout << "Handshake successful" << std::endl;

  // Send the file
  std::cout << "Sending file..." << std::endl;
  bool send_result = session->send_file(file_path, block_size);

  // Close the session
  session->close();

  // Clean up OpenSSL
  stx::crypto::cleanup();

  if (send_result) {
    std::cout << "File sent successfully" << std::endl;
    return 0;  // Success
  } else {
    std::cerr << "Error: Failed to send file" << std::endl;
    return 3;  // I/O error
  }
}