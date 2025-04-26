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

// Default client ID
const std::string DEFAULT_CLIENT_ID = "default";

void print_usage(const char* program_name) {
  std::cerr << "Usage: " << program_name
            << " [--id CLIENT_ID] <host> <port> <file_path> [block_size]" << std::endl;
  std::cerr << "  --id CLIENT_ID - Client identifier for authentication (default: "
            << DEFAULT_CLIENT_ID << ")" << std::endl;
  std::cerr << "  host          - Hostname or IP address of the receiver" << std::endl;
  std::cerr << "  port          - Port number of the receiver" << std::endl;
  std::cerr << "  file_path     - Path to the file to send" << std::endl;
  std::cerr << "  block_size    - Optional: Size of blocks for transfer (default: "
            << DEFAULT_BLOCK_SIZE << " bytes)" << std::endl;
}

int main(int argc, char* argv[]) {
  // Initialize OpenSSL
  if (!stx::crypto::initialize()) {
    std::cerr << "Error: Failed to initialize OpenSSL" << std::endl;
    return 1;
  }

  // Parse command line arguments
  std::string client_id = DEFAULT_CLIENT_ID;
  std::string host;
  uint16_t port;
  std::string file_path;
  uint32_t block_size = DEFAULT_BLOCK_SIZE;

  int arg_index = 1;

  // Check for client ID parameter
  if (arg_index < argc && std::string(argv[arg_index]) == "--id") {
    if (arg_index + 1 >= argc) {
      std::cerr << "Error: Missing CLIENT_ID after --id" << std::endl;
      print_usage(argv[0]);
      return 1;
    }
    client_id = argv[arg_index + 1];
    arg_index += 2;
  }

  // Check for required arguments
  if (argc - arg_index < 3) {
    print_usage(argv[0]);
    return 1;
  }

  host = argv[arg_index++];
  port = static_cast<uint16_t>(std::stoi(argv[arg_index++]));
  file_path = argv[arg_index++];

  // Optional block size
  if (arg_index < argc) {
    block_size = static_cast<uint32_t>(std::stoul(argv[arg_index++]));
  }

  // Check if the file exists and is readable
  if (!std::filesystem::exists(file_path)) {
    std::cerr << "Error: File does not exist: " << file_path << std::endl;
    return 3;  // I/O error
  }

  // Get file size
  std::uintmax_t file_size = std::filesystem::file_size(file_path);

  std::cout << "Client ID: " << client_id << std::endl;
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

  // Perform the handshake with client ID
  std::cout << "Performing handshake for client ID: " << client_id << "..." << std::endl;
  if (!session->client_handshake(client_id)) {
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