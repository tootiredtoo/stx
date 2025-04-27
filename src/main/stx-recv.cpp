#include <signal.h>
#include <asio.hpp>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "crypto/crypto.hpp"
#include "protocols/protocol.hpp"
#include "protocols/socket.hpp"

// Default listen port
constexpr uint16_t DEFAULT_PORT = 12345;

// Default keys directory
const std::string DEFAULT_KEYS_DIR = "./client_keys";

// Global flag for graceful shutdown
std::atomic<bool> running(true);

void signal_handler(int signal) {
  if (signal == SIGINT || signal == SIGTERM) {
    std::cerr << "\nReceived shutdown signal. Closing..." << std::endl;
    running = false;
  }
}

void print_usage(const char* program_name) {
  std::cerr << "Usage: " << program_name << " [options]" << std::endl;
  std::cerr << "Options:" << std::endl;
  std::cerr << "  --listen <port>      - Port to listen on (default: " << DEFAULT_PORT << ")"
            << std::endl;
  std::cerr << "  --out <directory>    - Directory to save received files" << std::endl;
  std::cerr << "  --keys <directory>   - Directory containing client keys (default: "
            << DEFAULT_KEYS_DIR << ")" << std::endl;
  std::cerr << "  --help               - Show this help message" << std::endl;
}

void handle_client(std::shared_ptr<asio::ip::tcp::socket> client_socket,
                   const std::string& output_dir) {
  // Get client information
  std::string client_ip;
  uint16_t client_port = 0;

  try {
    auto endpoint = client_socket->remote_endpoint();
    client_ip = endpoint.address().to_string();
    client_port = endpoint.port();
    std::cout << "Connection accepted from " << client_ip << ":" << client_port << std::endl;
  } catch (const std::exception& e) {
    std::cerr << "Error getting client information: " << e.what() << std::endl;
  }

  // Wrap the ASIO socket in our ISocket interface
  auto socket_wrapper = std::make_shared<AsioSocket>(client_socket);

  // Create a server session with the wrapped socket
  auto session = std::make_unique<stx::protocol::ServerSession>(socket_wrapper);

  // Perform the handshake
  if (!session->server_handshake()) {
    std::cerr << "Error: Handshake failed with client " << client_ip << ":" << client_port
              << std::endl;
    session->close();
    return;
  }

  std::cout << "Handshake successful with client ID: " << session->client_id() << " (" << client_ip
            << ":" << client_port << ")" << std::endl;

  // Receive the file
  bool receive_result = session->receive_file(output_dir);

  // Close the session
  session->close();

  if (!receive_result) {
    std::cerr << "Error: Failed to receive file from client " << session->client_id() << " ("
              << client_ip << ":" << client_port << ")" << std::endl;
  }
}

int main(int argc, char* argv[]) {
  // Initialize OpenSSL
  if (!stx::crypto::initialize()) {
    std::cerr << "Error: Failed to initialize OpenSSL" << std::endl;
    return 1;
  }

  // Set up signal handlers for graceful shutdown
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // Parse command line arguments
  uint16_t port = DEFAULT_PORT;
  std::string output_dir = ".";
  std::string keys_dir = DEFAULT_KEYS_DIR;

  int i = 1;
  while (i < argc) {
    std::string arg = argv[i];
    if (arg == "--listen" && i + 1 < argc) {
      port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
      i += 2;
    } else if (arg == "--out" && i + 1 < argc) {
      output_dir = argv[i + 1];
      i += 2;
    } else if (arg == "--keys" && i + 1 < argc) {
      keys_dir = argv[i + 1];
      i += 2;
    } else if (arg == "--help") {
      print_usage(argv[0]);
      return 0;
    } else {
      std::cerr << "Unknown option: " << arg << std::endl;
      print_usage(argv[0]);
      return 1;
    }
  }

  // Ensure the output directory exists
  if (!std::filesystem::exists(output_dir)) {
    try {
      std::filesystem::create_directories(output_dir);
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error: Failed to create output directory: " << e.what() << std::endl;
      return 3;  // I/O error
    }
  }

  // Ensure the keys directory exists
  if (!std::filesystem::exists(keys_dir)) {
    try {
      std::filesystem::create_directories(keys_dir);
    } catch (const std::filesystem::filesystem_error& e) {
      std::cerr << "Error: Failed to create keys directory: " << e.what() << std::endl;
      return 3;  // I/O error
    }
  }

  // Set the client keys directory
  stx::crypto::set_client_keys_directory(keys_dir);
  std::cout << "Using client keys directory: " << keys_dir << std::endl;

  try {
    // Create Asio IO context
    asio::io_context io_context;

    // Create acceptor
    auto acceptor = stx::protocol::create_server_acceptor(port);
    if (!acceptor) {
      std::cerr << "Error: Failed to create server acceptor" << std::endl;
      return 1;
    }

    std::cout << "Listening for connections on port " << port << std::endl;
    std::cout << "Files will be saved to: " << std::filesystem::absolute(output_dir) << std::endl;
    std::cout << "Press Ctrl+C to stop the server" << std::endl;

    // Vector to hold client threads
    std::vector<std::thread> client_threads;

    // Main server loop
    while (running) {
      // Create socket for new connection
      try {
        // Accept connection with timeout to check running flag periodically
        io_context.restart();

        // Set a deadline timer to allow checking the running flag
        asio::steady_timer timer(io_context, std::chrono::seconds(1));
        timer.async_wait([&](const asio::error_code&) {
          // This just wakes up the io_context
          if (!running) {
            acceptor->cancel();
          }
        });

        // Prepare for async accept
        auto raw_socket = std::make_shared<asio::ip::tcp::socket>(io_context);

        // Accept a connection
        acceptor->async_accept(*raw_socket, [&](const asio::error_code& error) {
          if (!error) {
            // Handle client in separate thread
            client_threads.emplace_back(
                [socket = raw_socket, output_dir]() mutable { handle_client(socket, output_dir); });

            // Detach the thread as we don't need to wait for it
            client_threads.back().detach();
          }
        });

        // Run the io_context until the timer or accept completes
        io_context.run();
      } catch (const asio::system_error& e) {
        if (e.code() == asio::error::operation_aborted) {
          // This is expected when we cancel during shutdown
          continue;
        }
        std::cerr << "Error accepting connection: " << e.what() << std::endl;
      } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
      }
    }

    // Close acceptor
    asio::error_code ec;
    acceptor->close(ec);

  } catch (const std::exception& e) {
    std::cerr << "Fatal error: " << e.what() << std::endl;
    stx::crypto::cleanup();
    return 1;
  }

  // Clean up OpenSSL
  stx::crypto::cleanup();

  std::cout << "Server stopped" << std::endl;
  return 0;
}