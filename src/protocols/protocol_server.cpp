#include <asio.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "protocols/protocol.hpp"

namespace stx {
namespace protocol {

// ServerSession implementation
ServerSession::ServerSession(std::shared_ptr<asio::ip::tcp::socket> socket)
    : socket_(socket), active_(socket && socket->is_open()) {
  // Initialize with random values until the handshake
  current_iv_ = crypto::generate_iv();
}

ServerSession::~ServerSession() {
  close();
}

bool ServerSession::send_message(const Message& message) {
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

std::unique_ptr<Message> ServerSession::receive_message() {
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

bool ServerSession::send_file(const std::string& file_path, uint32_t block_size) {
  // This is a server session, so this method is not implemented
  std::cerr << "Error: Servers don't initiate file sends. Attempted to send file: " << file_path
            << " with block size: " << block_size << " bytes" << std::endl;
  std::cerr << "Use a ClientSession to send files instead" << std::endl;
  return false;
}

bool ServerSession::receive_file(const std::string& output_dir) {
  try {
    // Receive file metadata
    auto metadata_msg_ptr = receive_message();
    if (!metadata_msg_ptr || metadata_msg_ptr->type() != MessageType::FILE_METADATA) {
      std::cerr << "Error: Expected FILE_METADATA message" << std::endl;
      return false;
    }

    FileMetadataMessage* metadata_msg = dynamic_cast<FileMetadataMessage*>(metadata_msg_ptr.get());
    const FileMetadata& metadata = metadata_msg->metadata();

    std::cout << "Receiving file: " << metadata.filename << std::endl;
    std::cout << "File size: " << metadata.filesize << " bytes" << std::endl;
    std::cout << "Block size: " << metadata.block_size << " bytes" << std::endl;
    std::cout << "Total blocks: " << metadata.total_blocks << std::endl;

    // Construct output file path - this will be our primary file path
    std::filesystem::path output_path = std::filesystem::path(output_dir) / metadata.filename;

    // Determine if we should resume or create a new file
    bool resuming = false;
    uint32_t next_block = 0;

    // Clear any previous received_blocks_ data
    received_blocks_.clear();

    // Check if the file already exists
    if (std::filesystem::exists(output_path)) {
      std::uintmax_t existing_size = std::filesystem::file_size(output_path);

      // If the file size matches exactly what we expect, try to resume
      if (existing_size == metadata.filesize) {
        resuming = true;
        next_block = 0;  // Start conservatively from the beginning

        std::cout << "Found existing file with matching size. Attempting to resume." << std::endl;
      }
      // If the file exists but is smaller, it might be an incomplete transfer
      else if (existing_size < metadata.filesize && existing_size > 0) {
        // Calculate how many complete blocks we have
        next_block = static_cast<uint32_t>(existing_size / metadata.block_size);

        if (next_block > 0 && next_block < metadata.total_blocks) {
          resuming = true;
          std::cout << "Found partially transferred file. Resuming from block " << next_block
                    << std::endl;
        } else {
          // If the file is too small or has inconsistent block count, start over
          resuming = false;
          next_block = 0;
          std::cout
              << "Found incomplete file but can't determine valid resume point. Starting over."
              << std::endl;
        }
      }
      // If the file is larger than expected or zero size, create a new file
      else {
        resuming = false;
        next_block = 0;
        std::cout << "Existing file has different size. Creating new file." << std::endl;
      }
    }

    // For the resume case, we'll use the existing file
    // For the non-resume case, we need to decide whether to overwrite or create a new file
    std::ofstream outfile;

    if (!resuming) {
      // If we're not resuming and the file exists, rename it with a timestamp
      if (std::filesystem::exists(output_path)) {
        auto now = std::chrono::system_clock::now();
        auto timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();

        std::filesystem::path new_path = output_path;
        std::string filename_base = metadata.filename;
        std::string extension = "";

        // Extract filename and extension
        size_t dot_pos = metadata.filename.find_last_of('.');
        if (dot_pos != std::string::npos) {
          filename_base = metadata.filename.substr(0, dot_pos);
          extension = metadata.filename.substr(dot_pos);
        }

        new_path = std::filesystem::path(output_dir) /
                   (filename_base + "_" + std::to_string(timestamp) + extension);

        // Safely rename the file to avoid overwriting
        try {
          std::filesystem::rename(output_path, new_path);
          std::cout << "Renamed existing file to: " << new_path.filename().string() << std::endl;
        } catch (const std::exception& e) {
          std::cerr << "Warning: Could not rename existing file: " << e.what() << std::endl;
          // If rename fails, we'll still try to create a new file
        }
      }

      // Create a new file
      outfile.open(output_path, std::ios::binary | std::ios::trunc);
      if (!outfile) {
        std::cerr << "Error: Failed to create output file: " << output_path << std::endl;
        return false;
      }

      std::cout << "Created new file: " << output_path.filename().string() << std::endl;
    } else {
      // Open existing file for update
      outfile.open(output_path, std::ios::binary | std::ios::in | std::ios::out);

      if (!outfile) {
        std::cerr << "Error: Failed to open existing file for resume: " << output_path << std::endl;
        // If we can't open it for resume, try creating a new file
        outfile.open(output_path, std::ios::binary | std::ios::trunc);
        if (!outfile) {
          std::cerr << "Error: Also failed to create new file: " << output_path << std::endl;
          return false;
        }
        resuming = false;
        next_block = 0;
      } else {
        std::cout << "Successfully opened file for resume: " << output_path.filename().string()
                  << std::endl;

        // Initialize received blocks map for already received blocks
        for (uint32_t i = 0; i < next_block; ++i) {
          received_blocks_[i] = true;
        }
      }
    }

    // Set our initial received count based on resume state
    uint32_t received_count = next_block;

    // Handle resume query if it comes next
    auto next_msg = receive_message();
    if (next_msg && next_msg->type() == MessageType::RESUME_QUERY) {
      ResumeQueryMessage* query = dynamic_cast<ResumeQueryMessage*>(next_msg.get());
      std::string requested_filename = query->filename();

      // Report our highest consecutive block
      uint32_t last_received_block = next_block > 0 ? (next_block - 1) : 0;

      std::cout << "Received resume query for file: " << requested_filename
                << ". Reporting last block: " << last_received_block << "/" << metadata.total_blocks
                << " (" << std::fixed << std::setprecision(1)
                << ((static_cast<double>(last_received_block + 1) / metadata.total_blocks) * 100.0)
                << "% complete)" << std::endl;

      // Send resume response
      ResumeResponseMessage response(requested_filename, last_received_block);
      if (!send_message(response)) {
        std::cerr << "Error: Failed to send resume response" << std::endl;
        outfile.close();
        return false;
      }

      // Get the next message
      next_msg = receive_message();
    }

    // Receive file blocks
    bool transfer_interrupted = false;

    while (received_count < metadata.total_blocks) {
      // Use the next_msg if we have one from resume query handling, otherwise receive new message
      std::unique_ptr<Message> block_msg_ptr;
      try {
        if (next_msg) {
          block_msg_ptr = std::move(next_msg);
          next_msg = nullptr;
        } else {
          block_msg_ptr = receive_message();
        }

        if (!block_msg_ptr) {
          std::cerr << "Error: Failed to receive message, connection may have been lost"
                    << std::endl;
          transfer_interrupted = true;
          break;
        }

        if (block_msg_ptr->type() != MessageType::FILE_BLOCK) {
          std::cerr << "Error: Expected FILE_BLOCK message, got type: "
                    << static_cast<int>(block_msg_ptr->type()) << std::endl;
          continue;  // Try the next message
        }

        FileBlockMessage* block_msg = dynamic_cast<FileBlockMessage*>(block_msg_ptr.get());
        uint32_t block_index = block_msg->block_index();
        const std::vector<uint8_t>& block_data = block_msg->block_data();
        uint32_t block_checksum = block_msg->checksum();

        // Verify block checksum
        uint32_t computed_checksum = crypto::calculate_crc32(block_data);
        bool checksum_valid = (computed_checksum == block_checksum);

        // Send acknowledgment
        BlockAckMessage ack(block_index, checksum_valid);
        if (!send_message(ack)) {
          std::cerr << "Error: Failed to send block acknowledgment" << std::endl;
          transfer_interrupted = true;
          break;
        }

        // If checksum is valid, write block to file
        if (checksum_valid) {
          // Seek to the correct position for this block
          std::streampos block_pos = static_cast<std::streampos>(block_index) * metadata.block_size;
          outfile.seekp(block_pos);

          if (!outfile) {
            std::cerr << "Error: Failed to seek to position " << block_pos << " for block "
                      << block_index << std::endl;
            continue;  // Try next block
          }

          // Write block data
          outfile.write(reinterpret_cast<const char*>(block_data.data()), block_data.size());
          outfile.flush();  // Flush after each block for safety

          if (!outfile) {
            std::cerr << "Error: Failed to write block " << block_index << " to file" << std::endl;
            continue;  // Try next block
          }

          // Mark block as received
          received_blocks_[block_index] = true;

          // Update received count if this was the next expected block
          if (block_index == received_count) {
            received_count++;

            // Check for any subsequent blocks that were already received
            while (received_blocks_.count(received_count) > 0 && received_blocks_[received_count]) {
              received_count++;
            }
          }
        } else {
          std::cerr << "Error: Checksum mismatch for block " << block_index << std::endl;
        }

        // Progress indicator with more details
        double progress = static_cast<double>(received_count) / metadata.total_blocks * 100.0;
        double remaining = 100.0 - progress;
        std::cout << "\rReceiving: [" << std::string(static_cast<int>(progress / 5), '#')
                  << std::string(static_cast<int>(remaining / 5), ' ') << "] " << std::fixed
                  << std::setprecision(1) << progress << "% (" << received_count << "/"
                  << metadata.total_blocks << " blocks, "
                  << (received_count * metadata.block_size) / (1024 * 1024) << "MB/"
                  << metadata.filesize / (1024 * 1024) << "MB)" << std::flush;
      } catch (const std::exception& e) {
        std::cerr << "Error during block reception: " << e.what() << std::endl;
        transfer_interrupted = true;
        break;
      }
    }

    // End the progress line
    std::cout << std::endl;

    // Make sure to flush and close the file
    outfile.flush();
    outfile.close();

    // Check if we completed or were interrupted
    if (received_count >= metadata.total_blocks) {
      std::cout << "File received successfully: " << output_path << std::endl;
      return true;
    } else if (transfer_interrupted) {
      std::cout << "File transfer interrupted. Received " << received_count << " of "
                << metadata.total_blocks << " blocks (" << std::fixed << std::setprecision(1)
                << (static_cast<double>(received_count) / metadata.total_blocks * 100.0)
                << "%). File can be resumed later." << std::endl;
      return true;  // Return true so we don't consider this a failure
    } else {
      std::cerr << "Error: Transfer incomplete but not interrupted" << std::endl;
      return false;
    }

  } catch (const std::exception& e) {
    std::cerr << "Error receiving file: " << e.what() << std::endl;
    return false;
  }
}

bool ServerSession::client_handshake() {
  // This is a server session, so this method is not implemented
  std::cerr << "Error: Server sessions don't perform client handshake" << std::endl;
  return false;
}

bool ServerSession::server_handshake() {
  try {
    std::cout << "Starting server handshake..." << std::endl;

    // Step 1: Generate server nonce
    std::cout << "Generating server nonce..." << std::endl;
    crypto::Nonce server_nonce = crypto::generate_nonce();

    // Step 2: Send Server Hello
    std::cout << "Sending SERVER_HELLO..." << std::endl;
    ServerHelloMessage server_hello(server_nonce);
    if (!send_message(server_hello)) {
      std::cerr << "Error: Failed to send SERVER_HELLO" << std::endl;
      return false;
    }

    // Step 3: Receive Client Hello with client ID
    std::cout << "Waiting for CLIENT_HELLO..." << std::endl;
    auto client_hello_msg_ptr = receive_message();
    if (!client_hello_msg_ptr) {
      std::cerr << "Error: Failed to receive any message" << std::endl;
      return false;
    }

    if (client_hello_msg_ptr->type() != MessageType::CLIENT_HELLO) {
      std::cerr << "Error: Expected CLIENT_HELLO message, got message type: "
                << static_cast<int>(client_hello_msg_ptr->type()) << std::endl;
      return false;
    }

    ClientHelloMessage* client_hello =
        dynamic_cast<ClientHelloMessage*>(client_hello_msg_ptr.get());

    // Get client ID and nonce
    std::string client_id = client_hello->client_id();
    crypto::Nonce client_nonce = client_hello->client_nonce();

    std::cout << "Received CLIENT_HELLO from client: " << client_id << std::endl;

    // Store client ID for later use
    client_id_ = client_id;

    // Step 4: Receive Client Auth
    std::cout << "Waiting for CLIENT_AUTH..." << std::endl;
    auto client_auth_msg_ptr = receive_message();
    if (!client_auth_msg_ptr) {
      std::cerr << "Error: Failed to receive any message after CLIENT_HELLO" << std::endl;
      return false;
    }

    if (client_auth_msg_ptr->type() != MessageType::CLIENT_AUTH) {
      std::cerr << "Error: Expected CLIENT_AUTH message, got message type: "
                << static_cast<int>(client_auth_msg_ptr->type()) << std::endl;
      return false;
    }

    ClientAuthMessage* client_auth = dynamic_cast<ClientAuthMessage*>(client_auth_msg_ptr.get());
    std::cout << "Received CLIENT_AUTH" << std::endl;

    // Step 5: Verify client's nonces match
    std::cout << "Verifying client nonces..." << std::endl;
    if (client_nonce != client_auth->client_nonce()) {
      std::cerr << "Error: Client nonce mismatch in client authentication" << std::endl;
      return false;
    }

    if (server_nonce != client_auth->server_nonce()) {
      std::cerr << "Error: Server nonce mismatch in client authentication" << std::endl;
      return false;
    }

    // Step 6: Get client-specific pre-shared key
    std::cout << "Getting key for client: " << client_id << std::endl;
    crypto::Key client_key = crypto::get_client_key(client_id);

    // Step 7: Verify client's HMAC with client-specific key
    std::cout << "Verifying client's HMAC..." << std::endl;
    std::vector<uint8_t> auth_data;
    auth_data.reserve(client_nonce.size() + server_nonce.size());
    auth_data.insert(auth_data.end(), client_nonce.begin(), client_nonce.end());
    auth_data.insert(auth_data.end(), server_nonce.begin(), server_nonce.end());

    if (!crypto::verify_hmac(client_key, auth_data, client_auth->hmac())) {
      std::cerr << "Error: Client authentication failed for client " << client_id << std::endl;

      // For debugging - print the keys
      std::stringstream ss;
      ss << "Client HMAC: ";
      for (auto b : client_auth->hmac()) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
      }
      std::cerr << ss.str() << std::endl;

      // Compute what we think the HMAC should be
      std::vector<uint8_t> computed_hmac = crypto::compute_hmac(client_key, auth_data);
      ss.str("");
      ss << "Server computed HMAC: ";
      for (auto b : computed_hmac) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
      }
      std::cerr << ss.str() << std::endl;

      return false;
    }

    std::cout << "Client " << client_id << " authenticated successfully" << std::endl;

    // Step 8: Generate server's HMAC
    std::cout << "Generating server HMAC..." << std::endl;
    std::vector<uint8_t> server_hmac = crypto::compute_hmac(client_key, auth_data);

    // Step 9: Send Server Auth
    std::cout << "Sending SERVER_AUTH..." << std::endl;
    ServerAuthMessage server_auth(server_hmac);
    if (!send_message(server_auth)) {
      std::cerr << "Error: Failed to send SERVER_AUTH" << std::endl;
      return false;
    }

    // Step 10: Receive Session Key
    std::cout << "Waiting for SESSION_KEY..." << std::endl;
    auto session_key_msg_ptr = receive_message();
    if (!session_key_msg_ptr) {
      std::cerr << "Error: Failed to receive any message after SERVER_AUTH" << std::endl;
      return false;
    }

    if (session_key_msg_ptr->type() != MessageType::SESSION_KEY) {
      std::cerr << "Error: Expected SESSION_KEY message, got message type: "
                << static_cast<int>(session_key_msg_ptr->type()) << std::endl;
      return false;
    }

    SessionKeyMessage* session_key_msg =
        dynamic_cast<SessionKeyMessage*>(session_key_msg_ptr.get());
    std::cout << "Received SESSION_KEY" << std::endl;

    // Step 11: Store session information
    std::cout << "Storing session information..." << std::endl;
    session_id_ = session_key_msg->session_id();
    current_iv_ = session_key_msg->iv();

    // Step 12: Derive session key
    std::cout << "Deriving session key..." << std::endl;
    session_key_ = crypto::derive_session_key(client_key, client_nonce, server_nonce);

    // Step 13: Send Session Confirm
    std::cout << "Sending SESSION_CONFIRM..." << std::endl;
    SessionConfirmMessage session_confirm(true);
    if (!send_message(session_confirm)) {
      std::cerr << "Error: Failed to send SESSION_CONFIRM" << std::endl;
      return false;
    }

    // Handshake successful
    std::cout << "Handshake completed successfully with client " << client_id << std::endl;
    active_ = true;
    return true;

  } catch (const std::exception& e) {
    std::cerr << "Error during handshake: " << e.what() << std::endl;
    active_ = false;
    return false;
  }
}

void ServerSession::close() {
  if (socket_ && socket_->is_open()) {
    asio::error_code ec;
    socket_->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    socket_->close(ec);
  }
  active_ = false;
}

bool ServerSession::is_active() const {
  return active_ && socket_ && socket_->is_open();
}

bool ServerSession::encrypt_and_send(const std::vector<uint8_t>& data) {
  try {
    // Generate a new IV for each encryption
    crypto::IV iv = crypto::generate_iv();

    // Authentication tag will be filled by the encrypt function
    crypto::AuthTag auth_tag;

    // Encrypt the data
    std::vector<uint8_t> ciphertext = crypto::encrypt(data, session_key_, iv, auth_tag);

    // Construct the message: [IV (12 bytes)][Auth Tag (16 bytes)][Ciphertext Size (4
    // bytes)][Ciphertext]
    std::vector<uint8_t> message;
    message.reserve(iv.size() + auth_tag.size() + 4 + ciphertext.size());

    // Add IV
    message.insert(message.end(), iv.begin(), iv.end());

    // Add Auth Tag
    message.insert(message.end(), auth_tag.begin(), auth_tag.end());

    // Add ciphertext size
    uint32_t size = static_cast<uint32_t>(ciphertext.size());
    message.push_back((size >> 24) & 0xFF);
    message.push_back((size >> 16) & 0xFF);
    message.push_back((size >> 8) & 0xFF);
    message.push_back(size & 0xFF);

    // Add ciphertext
    message.insert(message.end(), ciphertext.begin(), ciphertext.end());

    // Send the encrypted message
    return write_to_socket(*socket_, message);

  } catch (const std::exception& e) {
    std::cerr << "Error during encryption: " << e.what() << std::endl;
    return false;
  }
}

std::vector<uint8_t> ServerSession::receive_and_decrypt() {
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

// Create a server acceptor to listen for incoming connections
std::shared_ptr<asio::ip::tcp::acceptor> create_server_acceptor(uint16_t port) {
  try {
    // Create IO context
    auto io_context = std::make_shared<asio::io_context>();

    // Create acceptor
    auto acceptor = std::make_shared<asio::ip::tcp::acceptor>(
        *io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port));

    // Run the io_context in the background to keep it alive
    std::thread([io_ptr = io_context]() {
      asio::io_context::work work(*io_ptr);
      try {
        io_ptr->run();
      } catch (const std::exception& e) {
        std::cerr << "IO context error: " << e.what() << std::endl;
      }
    }).detach();

    std::cout << "Server listening on port " << port << std::endl;
    return acceptor;
  } catch (const std::exception& e) {
    std::cerr << "Error creating server acceptor: " << e.what() << std::endl;
    return nullptr;
  }
}

// Accept a new connection and create a server session
std::unique_ptr<ServerSession> accept_server_session(
    std::shared_ptr<asio::ip::tcp::acceptor> acceptor) {
  if (!acceptor || !acceptor->is_open()) {
    std::cerr << "Error: Invalid or closed acceptor" << std::endl;
    return nullptr;
  }

  try {
    // Create a socket for the new connection
    auto socket = std::make_shared<asio::ip::tcp::socket>(acceptor->get_executor());

    // Accept a connection
    acceptor->accept(*socket);

    std::cout << "Accepted connection from " << socket->remote_endpoint().address().to_string()
              << ":" << socket->remote_endpoint().port() << std::endl;

    // Create and return a server session with the connected socket
    return std::make_unique<ServerSession>(socket);
  } catch (const std::exception& e) {
    std::cerr << "Error accepting connection: " << e.what() << std::endl;
    return nullptr;
  }
}

}  // namespace protocol
}  // namespace stx