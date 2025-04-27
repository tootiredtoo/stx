#ifndef STX_PROTOCOL_HPP
#define STX_PROTOCOL_HPP

#include <array>
#include <asio.hpp>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include "crypto/crypto.hpp"

namespace stx {
namespace protocol {

// Forward declaration of message types
enum class MessageType : uint8_t;
class Message;

// Helper functions for socket I/O
std::vector<uint8_t> read_from_socket(asio::ip::tcp::socket& socket, size_t length);
bool write_to_socket(asio::ip::tcp::socket& socket, const std::vector<uint8_t>& data);

// File metadata structure
struct FileMetadata {
  std::string filename;
  std::uintmax_t filesize;
  uint32_t block_size;
  uint32_t total_blocks;
  std::string mime_type;
  uint32_t checksum;
};

// Client Session class declaration
class ClientSession {
 public:
  // Constructor takes an Asio socket
  explicit ClientSession(std::shared_ptr<asio::ip::tcp::socket> socket);

  // Destructor
  ~ClientSession();

  // Prevent copying
  ClientSession(const ClientSession&) = delete;
  ClientSession& operator=(const ClientSession&) = delete;

  // Message handling
  bool send_message(const Message& message);
  std::unique_ptr<Message> receive_message();

  // File transfer
  bool send_file(const std::string& file_path, uint32_t block_size = 1024 * 1024);
  bool receive_file(const std::string& output_dir);

  // Handshake functions
  bool client_handshake(const std::string& client_id);
  bool server_handshake();  // Not used by clients

  // Session management
  void close();
  bool is_active() const;

  // Encryption utilities
  bool encrypt_and_send(const std::vector<uint8_t>& data);
  std::vector<uint8_t> receive_and_decrypt();

  // Get client ID
  const std::string& client_id() const { return client_id_; }

 private:
  std::shared_ptr<asio::ip::tcp::socket> socket_;
  bool active_;
  std::string client_id_;
  crypto::SessionId session_id_;
  crypto::Key session_key_;
  crypto::IV current_iv_;
};

// Message factory function
std::unique_ptr<Message> create_message(MessageType type);

// Message types enum
enum class MessageType : uint8_t {
  UNKNOWN = 0,
  SERVER_HELLO = 1,
  CLIENT_HELLO = 2,
  CLIENT_AUTH = 3,
  SERVER_AUTH = 4,
  SESSION_KEY = 5,
  SESSION_CONFIRM = 6,
  FILE_METADATA = 7,
  FILE_BLOCK = 8,
  BLOCK_ACK = 9,
  RESUME_QUERY = 10,
  RESUME_RESPONSE = 11,
  ERROR_MSG = 255
};

// Base Message class
class Message {
 public:
  virtual ~Message() = default;
  virtual MessageType type() const = 0;
  virtual std::vector<uint8_t> serialize() const = 0;
  virtual void deserialize(const std::vector<uint8_t>& data) = 0;
};

// Message class declarations
class ServerHelloMessage : public Message {
 public:
  ServerHelloMessage() = default;
  explicit ServerHelloMessage(const crypto::Nonce& server_nonce);

  MessageType type() const override { return MessageType::SERVER_HELLO; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const crypto::Nonce& server_nonce() const { return server_nonce_; }

 private:
  crypto::Nonce server_nonce_;
};

class ClientHelloMessage : public Message {
 public:
  ClientHelloMessage() = default;
  ClientHelloMessage(const std::string& client_id, const crypto::Nonce& client_nonce);

  MessageType type() const override { return MessageType::CLIENT_HELLO; }

  std::vector<uint8_t> serialize() const override {
    std::vector<uint8_t> result;

    // Add client ID (string length + string content)
    uint32_t id_length = static_cast<uint32_t>(client_id_.length());
    result.push_back((id_length >> 24) & 0xFF);
    result.push_back((id_length >> 16) & 0xFF);
    result.push_back((id_length >> 8) & 0xFF);
    result.push_back(id_length & 0xFF);
    result.insert(result.end(), client_id_.begin(), client_id_.end());

    // Add client nonce
    result.insert(result.end(), client_nonce_.begin(), client_nonce_.end());

    return result;
  }

  void deserialize(const std::vector<uint8_t>& data) override {
    if (data.size() < 4) {
      throw std::runtime_error("Invalid ClientHelloMessage data size");
    }

    size_t pos = 0;

    // Extract client ID length
    uint32_t id_length =
        (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
        (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
    pos += 4;

    if (pos + id_length > data.size()) {
      throw std::runtime_error("Invalid client ID length in ClientHelloMessage");
    }

    // Extract client ID
    client_id_ = std::string(data.begin() + pos, data.begin() + pos + id_length);
    pos += id_length;

    // Extract client nonce
    if (pos + client_nonce_.size() > data.size()) {
      throw std::runtime_error("Invalid data size for client nonce in ClientHelloMessage");
    }

    std::copy(data.begin() + pos, data.begin() + pos + client_nonce_.size(), client_nonce_.begin());
  }

  const std::string& client_id() const { return client_id_; }
  const crypto::Nonce& client_nonce() const { return client_nonce_; }

 private:
  std::string client_id_;
  crypto::Nonce client_nonce_;
};

class ClientAuthMessage : public Message {
 public:
  ClientAuthMessage() = default;
  ClientAuthMessage(const crypto::Nonce& client_nonce, const crypto::Nonce& server_nonce,
                    const std::vector<uint8_t>& hmac);

  MessageType type() const override { return MessageType::CLIENT_AUTH; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const crypto::Nonce& client_nonce() const { return client_nonce_; }
  const crypto::Nonce& server_nonce() const { return server_nonce_; }
  const std::vector<uint8_t>& hmac() const { return hmac_; }

 private:
  crypto::Nonce client_nonce_;
  crypto::Nonce server_nonce_;
  std::vector<uint8_t> hmac_;
};

class ServerAuthMessage : public Message {
 public:
  ServerAuthMessage() = default;
  explicit ServerAuthMessage(const std::vector<uint8_t>& hmac);

  MessageType type() const override { return MessageType::SERVER_AUTH; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const std::vector<uint8_t>& hmac() const { return hmac_; }

 private:
  std::vector<uint8_t> hmac_;
};

class SessionKeyMessage : public Message {
 public:
  SessionKeyMessage() = default;
  SessionKeyMessage(const crypto::SessionId& session_id, const crypto::IV& iv);

  MessageType type() const override { return MessageType::SESSION_KEY; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const crypto::SessionId& session_id() const { return session_id_; }
  const crypto::IV& iv() const { return iv_; }

 private:
  crypto::SessionId session_id_;
  crypto::IV iv_;
};

class SessionConfirmMessage : public Message {
 public:
  SessionConfirmMessage() = default;
  explicit SessionConfirmMessage(bool success);

  MessageType type() const override { return MessageType::SESSION_CONFIRM; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  bool success() const { return success_; }

 private:
  bool success_;
};

class FileMetadataMessage : public Message {
 public:
  FileMetadataMessage() = default;
  explicit FileMetadataMessage(const FileMetadata& metadata);

  MessageType type() const override { return MessageType::FILE_METADATA; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const FileMetadata& metadata() const { return metadata_; }

 private:
  FileMetadata metadata_;
};

class FileBlockMessage : public Message {
 public:
  FileBlockMessage() = default;
  FileBlockMessage(uint32_t block_index, const std::vector<uint8_t>& block_data, uint32_t checksum);

  MessageType type() const override { return MessageType::FILE_BLOCK; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  uint32_t block_index() const { return block_index_; }
  const std::vector<uint8_t>& block_data() const { return block_data_; }
  uint32_t checksum() const { return checksum_; }

 private:
  uint32_t block_index_;
  std::vector<uint8_t> block_data_;
  uint32_t checksum_;
};

class BlockAckMessage : public Message {
 public:
  BlockAckMessage() = default;
  BlockAckMessage(uint32_t block_index, bool success);

  MessageType type() const override { return MessageType::BLOCK_ACK; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  uint32_t block_index() const { return block_index_; }
  bool success() const { return success_; }

 private:
  uint32_t block_index_;
  bool success_;
};

class ResumeQueryMessage : public Message {
 public:
  ResumeQueryMessage() = default;
  explicit ResumeQueryMessage(const std::string& filename);

  MessageType type() const override { return MessageType::RESUME_QUERY; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const std::string& filename() const { return filename_; }

 private:
  std::string filename_;
};

class ResumeResponseMessage : public Message {
 public:
  ResumeResponseMessage() = default;
  ResumeResponseMessage(const std::string& filename, uint32_t last_block_received);

  MessageType type() const override { return MessageType::RESUME_RESPONSE; }
  std::vector<uint8_t> serialize() const override;
  void deserialize(const std::vector<uint8_t>& data) override;

  const std::string& filename() const { return filename_; }
  uint32_t last_block_received() const { return last_block_received_; }

 private:
  std::string filename_;
  uint32_t last_block_received_;
};

class ServerSession {
 public:
  explicit ServerSession(std::shared_ptr<asio::ip::tcp::socket> socket);

  ~ServerSession();

  ServerSession(const ServerSession&) = delete;
  ServerSession& operator=(const ServerSession&) = delete;

  bool send_message(const Message& message);
  std::unique_ptr<Message> receive_message();

  bool send_file(const std::string& file_path, uint32_t block_size = 1024 * 1024);
  bool receive_file(const std::string& output_dir);

  bool client_handshake();  // Not used by servers
  bool server_handshake();

  void close();
  bool is_active() const;

  bool encrypt_and_send(const std::vector<uint8_t>& data);
  std::vector<uint8_t> receive_and_decrypt();

  const std::string& client_id() const { return client_id_; }

 private:
  std::shared_ptr<asio::ip::tcp::socket> socket_;
  bool active_;
  std::string client_id_;
  crypto::SessionId session_id_;
  crypto::Key session_key_;
  crypto::IV current_iv_;
  std::map<uint32_t, bool> received_blocks_; 
};

// Factory functions to create sessions
std::unique_ptr<ClientSession> create_client_session(const std::string& host, uint16_t port);
std::shared_ptr<asio::ip::tcp::acceptor> create_server_acceptor(uint16_t port);
std::unique_ptr<ServerSession> accept_server_session(
    std::shared_ptr<asio::ip::tcp::acceptor> acceptor);

}  // namespace protocol
}  // namespace stx

#endif  // STX_PROTOCOL_HPP