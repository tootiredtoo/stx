#include <algorithm>
#include <asio.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <thread>
#include "protocols/protocol.hpp"

namespace stx {
namespace protocol {

// Helper function to read data from socket using Asio
std::vector<uint8_t> read_from_socket(asio::ip::tcp::socket& socket, size_t length) {
  std::vector<uint8_t> buffer(length);
  size_t total_read = 0;

  while (total_read < length) {
    try {
      asio::error_code ec;
      size_t bytes_read =
          asio::read(socket, asio::buffer(buffer.data() + total_read, length - total_read),
                     asio::transfer_at_least(1), ec);

      if (ec) {
        throw std::runtime_error("Connection closed or error while reading: " + ec.message());
      }

      if (bytes_read == 0) {
        throw std::runtime_error("Connection closed while reading");
      }

      total_read += bytes_read;
    } catch (const std::exception& e) {
      throw std::runtime_error(std::string("Error reading from socket: ") + e.what());
    }
  }

  return buffer;
}

// Helper function to write data to socket using Asio
bool write_to_socket(asio::ip::tcp::socket& socket, const std::vector<uint8_t>& data) {
  try {
    size_t total_sent = 0;

    while (total_sent < data.size()) {
      asio::error_code ec;
      size_t bytes_sent =
          asio::write(socket, asio::buffer(data.data() + total_sent, data.size() - total_sent),
                      asio::transfer_at_least(1), ec);

      if (ec) {
        std::cerr << "Error writing to socket: " << ec.message() << std::endl;
        return false;
      }

      if (bytes_sent == 0) {
        std::cerr << "Connection closed while writing" << std::endl;
        return false;
      }

      total_sent += bytes_sent;
    }

    return true;
  } catch (const std::exception& e) {
    std::cerr << "Error writing to socket: " << e.what() << std::endl;
    return false;
  }
}

// ClientSession implementation
ClientSession::ClientSession(std::shared_ptr<asio::ip::tcp::socket> socket)
    : socket_(socket), active_(socket && socket->is_open()) {
  // Initialize with random values until the handshake
  current_iv_ = crypto::generate_iv();
}

ClientSession::~ClientSession() {
  close();
}

bool ClientSession::send_message(const Message& message) {
  try {
    // Serialize the message
    std::vector<uint8_t> serialized = message.serialize();

    // Construct the message header (4 bytes for size, 1 byte for type)
    std::vector<uint8_t> header(5);
    uint32_t size = static_cast<uint32_t>(serialized.size());
    header[0] = (size >> 24) & 0xFF;
    header[1] = (size >> 16) & 0xFF;
    header[2] = (size >> 8) & 0xFF;
    header[3] = size & 0xFF;
    header[4] = static_cast<uint8_t>(message.type());

    // Send the header
    if (!write_to_socket(*socket_, header)) {
      std::cerr << "Error: Failed to send message header" << std::endl;
      active_ = false;
      return false;
    }

    // Send the message body
    if (!write_to_socket(*socket_, serialized)) {
      std::cerr << "Error: Failed to send message body" << std::endl;
      active_ = false;
      return false;
    }

    return true;
  } catch (const std::exception& e) {
    std::cerr << "Error sending message: " << e.what() << std::endl;
    active_ = false;
    return false;
  }
}

std::unique_ptr<Message> ClientSession::receive_message() {
  try {
    // Read the message header (4 bytes for size, 1 byte for type)
    std::vector<uint8_t> header = read_from_socket(*socket_, 5);

    // Parse the header
    uint32_t size = (static_cast<uint32_t>(header[0]) << 24) |
                    (static_cast<uint32_t>(header[1]) << 16) |
                    (static_cast<uint32_t>(header[2]) << 8) | static_cast<uint32_t>(header[3]);

    MessageType type = static_cast<MessageType>(header[4]);

    // Read the message body
    std::vector<uint8_t> body = read_from_socket(*socket_, size);

    // Create and deserialize the message
    std::unique_ptr<Message> message = create_message(type);
    if (!message) {
      throw std::runtime_error("Unknown message type");
    }

    message->deserialize(body);
    return message;
  } catch (const std::exception& e) {
    std::cerr << "Error receiving message: " << e.what() << std::endl;
    active_ = false;
    return nullptr;
  }
}

bool ClientSession::send_file(const std::string& file_path, uint32_t block_size) {
  // Check if the file exists
  if (!std::filesystem::exists(file_path)) {
    std::cerr << "Error: File does not exist: " << file_path << std::endl;
    return false;
  }

  // Open the file
  std::ifstream file(file_path, std::ios::binary);
  if (!file) {
    std::cerr << "Error: Failed to open file: " << file_path << std::endl;
    return false;
  }

  // Get file size and calculate total blocks
  std::uintmax_t file_size = std::filesystem::file_size(file_path);
  uint32_t total_blocks = static_cast<uint32_t>((file_size + block_size - 1) / block_size);

  // Get filename from path
  std::string filename = std::filesystem::path(file_path).filename().string();

  // Calculate file checksum (simplified - just a placeholder)
  uint32_t file_checksum = 0;

  // Prepare and send file metadata
  FileMetadata metadata;
  metadata.filename = filename;
  metadata.filesize = file_size;
  metadata.block_size = block_size;
  metadata.total_blocks = total_blocks;
  metadata.mime_type = "application/octet-stream";  // Default MIME type
  metadata.checksum = file_checksum;

  FileMetadataMessage metadata_msg(metadata);
  if (!send_message(metadata_msg)) {
    std::cerr << "Error: Failed to send file metadata" << std::endl;
    return false;
  }

  // Buffer for reading blocks
  std::vector<uint8_t> block_buffer(block_size);

  // Send file blocks
  uint32_t block_index = 0;
  std::streamsize bytes_read;

  while (block_index < total_blocks) {
    // Read a block from the file
    file.read(reinterpret_cast<char*>(block_buffer.data()), block_size);
    bytes_read = file.gcount();

    // Resize buffer to actual bytes read
    if (bytes_read < static_cast<std::streamsize>(block_size)) {
      block_buffer.resize(bytes_read);
    }

    // Calculate block checksum
    uint32_t block_checksum = crypto::calculate_crc32(block_buffer);

    // Send the block
    FileBlockMessage block_msg(block_index, block_buffer, block_checksum);
    if (!send_message(block_msg)) {
      std::cerr << "Error: Failed to send block " << block_index << std::endl;
      return false;
    }

    // Wait for acknowledgment
    std::unique_ptr<Message> ack_msg = receive_message();
    if (!ack_msg || ack_msg->type() != MessageType::BLOCK_ACK) {
      std::cerr << "Error: Failed to receive acknowledgment for block " << block_index << std::endl;
      return false;
    }

    BlockAckMessage* ack = dynamic_cast<BlockAckMessage*>(ack_msg.get());
    if (!ack || !ack->success()) {
      std::cerr << "Error: Block " << block_index << " was not acknowledged successfully"
                << std::endl;
      // Retry sending this block
      file.seekg(block_index * block_size);
      continue;
    }

    // Move to the next block
    block_index++;

    // Progress indicator
    double progress = static_cast<double>(block_index) / total_blocks * 100.0;
    std::cout << "\rProgress: " << std::fixed << std::setprecision(1) << progress << "% ("
              << block_index << "/" << total_blocks << " blocks)" << std::flush;
  }

  std::cout << std::endl;
  return true;
}

bool ClientSession::receive_file(const std::string& output_dir) {
  // This is a client session, so this method is not implemented
  std::cerr
      << "Error: Clients don't receive files directly. Attempted to receive file to directory: "
      << output_dir << std::endl;
  std::cerr << "Use a ServerSession to receive files instead" << std::endl;
  std::cerr << "If you want to download a file, use a server to send the file to the client, "
            << "and the client to send a request to the server" << std::endl;
  return false;
}

bool ClientSession::client_handshake(const std::string& client_id) {
  try {
    std::cout << "Starting client handshake for client " << client_id << "..." << std::endl;

    // Store client ID
    client_id_ = client_id;

    // Step 1: Receive Server Hello
    std::cout << "Waiting for SERVER_HELLO..." << std::endl;
    auto server_hello_msg_ptr = receive_message();
    if (!server_hello_msg_ptr) {
      std::cerr << "Error: Failed to receive any message" << std::endl;
      return false;
    }

    if (server_hello_msg_ptr->type() != MessageType::SERVER_HELLO) {
      std::cerr << "Error: Expected SERVER_HELLO message, got message type: "
                << static_cast<int>(server_hello_msg_ptr->type()) << std::endl;
      return false;
    }

    ServerHelloMessage* server_hello =
        dynamic_cast<ServerHelloMessage*>(server_hello_msg_ptr.get());
    crypto::Nonce server_nonce = server_hello->server_nonce();
    std::cout << "Received SERVER_HELLO" << std::endl;

    // Step 2: Send Client Hello with client ID
    std::cout << "Sending CLIENT_HELLO with ID: " << client_id << std::endl;
    crypto::Nonce client_nonce = crypto::generate_nonce();
    ClientHelloMessage client_hello(client_id, client_nonce);
    if (!send_message(client_hello)) {
      std::cerr << "Error: Failed to send CLIENT_HELLO" << std::endl;
      return false;
    }

    // Step 3: Generate authentication data
    std::cout << "Generating authentication data..." << std::endl;

    // Get client-specific key
    crypto::Key client_key = crypto::get_client_key(client_id);

    // Combine nonces for auth data
    std::vector<uint8_t> auth_data;
    auth_data.reserve(client_nonce.size() + server_nonce.size());
    auth_data.insert(auth_data.end(), client_nonce.begin(), client_nonce.end());
    auth_data.insert(auth_data.end(), server_nonce.begin(), server_nonce.end());

    // Compute HMAC with client-specific key
    std::vector<uint8_t> client_hmac = crypto::compute_hmac(client_key, auth_data);

    // Step 4: Send Client Auth
    std::cout << "Sending CLIENT_AUTH..." << std::endl;
    ClientAuthMessage client_auth(client_nonce, server_nonce, client_hmac);
    if (!send_message(client_auth)) {
      std::cerr << "Error: Failed to send CLIENT_AUTH" << std::endl;
      return false;
    }

    // Step 5: Receive Server Auth
    std::cout << "Waiting for SERVER_AUTH..." << std::endl;
    auto server_auth_msg_ptr = receive_message();
    if (!server_auth_msg_ptr) {
      std::cerr << "Error: Failed to receive any message after CLIENT_AUTH" << std::endl;
      return false;
    }

    if (server_auth_msg_ptr->type() != MessageType::SERVER_AUTH) {
      std::cerr << "Error: Expected SERVER_AUTH message, got message type: "
                << static_cast<int>(server_auth_msg_ptr->type()) << std::endl;
      return false;
    }

    ServerAuthMessage* server_auth = dynamic_cast<ServerAuthMessage*>(server_auth_msg_ptr.get());
    std::cout << "Received SERVER_AUTH" << std::endl;

    // Verify server's HMAC with client-specific key
    if (!crypto::verify_hmac(client_key, auth_data, server_auth->hmac())) {
      std::cerr << "Error: Server authentication failed" << std::endl;
      return false;
    }
    std::cout << "Server authentication successful" << std::endl;

    // Step 6: Derive session key
    std::cout << "Deriving session key..." << std::endl;
    session_key_ = crypto::derive_session_key(client_key, client_nonce, server_nonce);

    // Step 7: Generate session ID and initial IV
    session_id_ = crypto::generate_session_id();
    current_iv_ = crypto::generate_iv();

    // Step 8: Send Session Key
    std::cout << "Sending SESSION_KEY..." << std::endl;
    SessionKeyMessage session_key_msg(session_id_, current_iv_);
    if (!send_message(session_key_msg)) {
      std::cerr << "Error: Failed to send SESSION_KEY" << std::endl;
      return false;
    }

    // Step 9: Receive Session Confirm
    std::cout << "Waiting for SESSION_CONFIRM..." << std::endl;
    auto session_confirm_msg_ptr = receive_message();
    if (!session_confirm_msg_ptr) {
      std::cerr << "Error: Failed to receive any message after SESSION_KEY" << std::endl;
      return false;
    }

    if (session_confirm_msg_ptr->type() != MessageType::SESSION_CONFIRM) {
      std::cerr << "Error: Expected SESSION_CONFIRM message, got message type: "
                << static_cast<int>(session_confirm_msg_ptr->type()) << std::endl;
      return false;
    }

    SessionConfirmMessage* session_confirm =
        dynamic_cast<SessionConfirmMessage*>(session_confirm_msg_ptr.get());
    if (!session_confirm->success()) {
      std::cerr << "Error: Session establishment failed" << std::endl;
      return false;
    }

    // Handshake successful
    std::cout << "Handshake completed successfully for client " << client_id << std::endl;
    active_ = true;
    return true;

  } catch (const std::exception& e) {
    std::cerr << "Error during handshake: " << e.what() << std::endl;
    active_ = false;
    return false;
  }
}

bool ClientSession::server_handshake() {
  // This is a client session, so this method is not implemented
  std::cerr << "Error: Client sessions don't perform server handshake" << std::endl;
  return false;
}

void ClientSession::close() {
  if (socket_ && socket_->is_open()) {
    asio::error_code ec;
    socket_->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket_->close(ec);
  }
  active_ = false;
}

bool ClientSession::is_active() const {
  return active_ && socket_ && socket_->is_open();
}

bool ClientSession::encrypt_and_send(const std::vector<uint8_t>& data) {
  try {
    // Generate a new IV for each encryption
    crypto::IV iv = crypto::generate_iv();

    // Authentication tag will be filled by the encrypt function
    crypto::AuthTag auth_tag;

    // Encrypt the data
    std::vector<uint8_t> ciphertext = crypto::encrypt(data, session_key_, iv, auth_tag);

    // Construct the message: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext]
    std::vector<uint8_t> message;
    message.reserve(iv.size() + auth_tag.size() + ciphertext.size());
    message.insert(message.end(), iv.begin(), iv.end());
    message.insert(message.end(), auth_tag.begin(), auth_tag.end());
    message.insert(message.end(), ciphertext.begin(), ciphertext.end());

    // Send the encrypted message
    return write_to_socket(*socket_, message);

  } catch (const std::exception& e) {
    std::cerr << "Error during encryption: " << e.what() << std::endl;
    return false;
  }
}

std::vector<uint8_t> ClientSession::receive_and_decrypt() {
  try {
    // Read the IV (12 bytes)
    crypto::IV iv;
    std::vector<uint8_t> iv_data = read_from_socket(*socket_, iv.size());
    std::copy(iv_data.begin(), iv_data.end(), iv.begin());

    // Read the authentication tag (16 bytes)
    crypto::AuthTag auth_tag;
    std::vector<uint8_t> tag_data = read_from_socket(*socket_, auth_tag.size());
    std::copy(tag_data.begin(), tag_data.end(), auth_tag.begin());

    // Read the message size
    std::vector<uint8_t> size_data = read_from_socket(*socket_, 4);
    uint32_t ciphertext_size =
        (static_cast<uint32_t>(size_data[0]) << 24) | (static_cast<uint32_t>(size_data[1]) << 16) |
        (static_cast<uint32_t>(size_data[2]) << 8) | static_cast<uint32_t>(size_data[3]);

    // Read the ciphertext
    std::vector<uint8_t> ciphertext = read_from_socket(*socket_, ciphertext_size);

    // Decrypt the message
    return crypto::decrypt(ciphertext, session_key_, iv, auth_tag);

  } catch (const std::exception& e) {
    std::cerr << "Error during decryption: " << e.what() << std::endl;
    throw;
  }
}

// Factory function to create a client session connected to a given host and port
std::unique_ptr<ClientSession> create_client_session(const std::string& host, uint16_t port) {
  try {
    // Create IO context
    auto io_context = std::make_shared<asio::io_context>();

    // Resolve endpoint
    asio::ip::tcp::resolver resolver(*io_context);
    asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(host, std::to_string(port));

    // Create and connect socket
    auto socket = std::make_shared<asio::ip::tcp::socket>(*io_context);
    asio::connect(*socket, endpoints);

    // Run the io_context in the background to keep it alive
    // This is needed for asynchronous operations
    std::thread([io_ptr = io_context]() {
      asio::io_context::work work(*io_ptr);
      try {
        io_ptr->run();
      } catch (const std::exception& e) {
        std::cerr << "IO context error: " << e.what() << std::endl;
      }
    }).detach();

    // Create client session
    return std::make_unique<ClientSession>(socket);
  } catch (const std::exception& e) {
    std::cerr << "Error creating client session: " << e.what() << std::endl;
    return nullptr;
  }
}

}  // namespace protocol
}  // namespace stx