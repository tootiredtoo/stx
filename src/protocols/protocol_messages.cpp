#include <cstring>
#include <memory>
#include <stdexcept>
#include "protocols/protocol.hpp"

namespace stx {
namespace protocol {

// Helper functions for string serialization
std::vector<uint8_t> serialize_string(const std::string& str) {
  std::vector<uint8_t> result;

  // Add the string size (4 bytes)
  uint32_t size = static_cast<uint32_t>(str.size());
  result.push_back((size >> 24) & 0xFF);
  result.push_back((size >> 16) & 0xFF);
  result.push_back((size >> 8) & 0xFF);
  result.push_back(size & 0xFF);

  // Add the string content
  result.insert(result.end(), str.begin(), str.end());

  return result;
}

std::string deserialize_string(const std::vector<uint8_t>& data, size_t& pos) {
  if (pos + 4 > data.size()) {
    throw std::runtime_error("Not enough data to deserialize string size");
  }

  // Extract string size
  uint32_t size =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  if (pos + size > data.size()) {
    throw std::runtime_error("Not enough data to deserialize string content");
  }

  // Extract string content
  std::string result(data.begin() + pos, data.begin() + pos + size);
  pos += size;

  return result;
}

// Constructor implementations
ServerHelloMessage::ServerHelloMessage(const crypto::Nonce& server_nonce)
    : server_nonce_(server_nonce) {}

ClientHelloMessage::ClientHelloMessage(const crypto::Nonce& client_nonce)
    : client_nonce_(client_nonce) {}

ClientAuthMessage::ClientAuthMessage(const crypto::Nonce& client_nonce,
                                     const crypto::Nonce& server_nonce,
                                     const std::vector<uint8_t>& hmac)
    : client_nonce_(client_nonce), server_nonce_(server_nonce), hmac_(hmac) {}

ServerAuthMessage::ServerAuthMessage(const std::vector<uint8_t>& hmac) : hmac_(hmac) {}

SessionKeyMessage::SessionKeyMessage(const crypto::SessionId& session_id, const crypto::IV& iv)
    : session_id_(session_id), iv_(iv) {}

SessionConfirmMessage::SessionConfirmMessage(bool success) : success_(success) {}

FileMetadataMessage::FileMetadataMessage(const FileMetadata& metadata) : metadata_(metadata) {}

FileBlockMessage::FileBlockMessage(uint32_t block_index, const std::vector<uint8_t>& block_data,
                                   uint32_t checksum)
    : block_index_(block_index), block_data_(block_data), checksum_(checksum) {}

BlockAckMessage::BlockAckMessage(uint32_t block_index, bool success)
    : block_index_(block_index), success_(success) {}

// ServerHelloMessage implementation
std::vector<uint8_t> ServerHelloMessage::serialize() const {
  std::vector<uint8_t> result(server_nonce_.begin(), server_nonce_.end());
  return result;
}

void ServerHelloMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() != server_nonce_.size()) {
    throw std::runtime_error("Invalid ServerHelloMessage data size");
  }
  std::copy(data.begin(), data.end(), server_nonce_.begin());
}

// ClientHelloMessage implementation
std::vector<uint8_t> ClientHelloMessage::serialize() const {
  std::vector<uint8_t> result(client_nonce_.begin(), client_nonce_.end());
  return result;
}

void ClientHelloMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() != client_nonce_.size()) {
    throw std::runtime_error("Invalid ClientHelloMessage data size");
  }
  std::copy(data.begin(), data.end(), client_nonce_.begin());
}

// ClientAuthMessage implementation
std::vector<uint8_t> ClientAuthMessage::serialize() const {
  std::vector<uint8_t> result;

  // Add client nonce
  result.insert(result.end(), client_nonce_.begin(), client_nonce_.end());

  // Add server nonce
  result.insert(result.end(), server_nonce_.begin(), server_nonce_.end());

  // Add HMAC size and content
  uint32_t hmac_size = static_cast<uint32_t>(hmac_.size());
  result.push_back((hmac_size >> 24) & 0xFF);
  result.push_back((hmac_size >> 16) & 0xFF);
  result.push_back((hmac_size >> 8) & 0xFF);
  result.push_back(hmac_size & 0xFF);
  result.insert(result.end(), hmac_.begin(), hmac_.end());

  return result;
}

void ClientAuthMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() < client_nonce_.size() + server_nonce_.size() + 4) {
    throw std::runtime_error("Invalid ClientAuthMessage data size");
  }

  size_t pos = 0;

  // Extract client nonce
  std::copy(data.begin() + pos, data.begin() + pos + client_nonce_.size(), client_nonce_.begin());
  pos += client_nonce_.size();

  // Extract server nonce
  std::copy(data.begin() + pos, data.begin() + pos + server_nonce_.size(), server_nonce_.begin());
  pos += server_nonce_.size();

  // Extract HMAC size
  uint32_t hmac_size =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  if (pos + hmac_size > data.size()) {
    throw std::runtime_error("Invalid HMAC size in ClientAuthMessage");
  }

  // Extract HMAC
  hmac_.assign(data.begin() + pos, data.begin() + pos + hmac_size);
}

// ServerAuthMessage implementation
std::vector<uint8_t> ServerAuthMessage::serialize() const {
  std::vector<uint8_t> result;

  // Add HMAC size and content
  uint32_t hmac_size = static_cast<uint32_t>(hmac_.size());
  result.push_back((hmac_size >> 24) & 0xFF);
  result.push_back((hmac_size >> 16) & 0xFF);
  result.push_back((hmac_size >> 8) & 0xFF);
  result.push_back(hmac_size & 0xFF);
  result.insert(result.end(), hmac_.begin(), hmac_.end());

  return result;
}

void ServerAuthMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() < 4) {
    throw std::runtime_error("Invalid ServerAuthMessage data size");
  }

  size_t pos = 0;

  // Extract HMAC size
  uint32_t hmac_size =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  if (pos + hmac_size > data.size()) {
    throw std::runtime_error("Invalid HMAC size in ServerAuthMessage");
  }

  // Extract HMAC
  hmac_.assign(data.begin() + pos, data.begin() + pos + hmac_size);
}

// SessionKeyMessage implementation
std::vector<uint8_t> SessionKeyMessage::serialize() const {
  std::vector<uint8_t> result;

  // Add session ID
  result.insert(result.end(), session_id_.begin(), session_id_.end());

  // Add initial IV
  result.insert(result.end(), iv_.begin(), iv_.end());

  return result;
}

void SessionKeyMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() != session_id_.size() + iv_.size()) {
    throw std::runtime_error("Invalid SessionKeyMessage data size");
  }

  size_t pos = 0;

  // Extract session ID
  std::copy(data.begin() + pos, data.begin() + pos + session_id_.size(), session_id_.begin());
  pos += session_id_.size();

  // Extract initial IV
  std::copy(data.begin() + pos, data.begin() + pos + iv_.size(), iv_.begin());
}

// SessionConfirmMessage implementation
std::vector<uint8_t> SessionConfirmMessage::serialize() const {
  std::vector<uint8_t> result(1);
  result[0] = success_ ? 1 : 0;
  return result;
}

void SessionConfirmMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() != 1) {
    throw std::runtime_error("Invalid SessionConfirmMessage data size");
  }
  success_ = (data[0] != 0);
}

// FileMetadataMessage implementation
std::vector<uint8_t> FileMetadataMessage::serialize() const {
  std::vector<uint8_t> result;

  // Add filename
  std::vector<uint8_t> filename_data = serialize_string(metadata_.filename);
  result.insert(result.end(), filename_data.begin(), filename_data.end());

  // Add filesize
  result.push_back((metadata_.filesize >> 56) & 0xFF);
  result.push_back((metadata_.filesize >> 48) & 0xFF);
  result.push_back((metadata_.filesize >> 40) & 0xFF);
  result.push_back((metadata_.filesize >> 32) & 0xFF);
  result.push_back((metadata_.filesize >> 24) & 0xFF);
  result.push_back((metadata_.filesize >> 16) & 0xFF);
  result.push_back((metadata_.filesize >> 8) & 0xFF);
  result.push_back(metadata_.filesize & 0xFF);

  // Add block_size
  result.push_back((metadata_.block_size >> 24) & 0xFF);
  result.push_back((metadata_.block_size >> 16) & 0xFF);
  result.push_back((metadata_.block_size >> 8) & 0xFF);
  result.push_back(metadata_.block_size & 0xFF);

  // Add total_blocks
  result.push_back((metadata_.total_blocks >> 24) & 0xFF);
  result.push_back((metadata_.total_blocks >> 16) & 0xFF);
  result.push_back((metadata_.total_blocks >> 8) & 0xFF);
  result.push_back(metadata_.total_blocks & 0xFF);

  // Add mime_type
  std::vector<uint8_t> mime_type_data = serialize_string(metadata_.mime_type);
  result.insert(result.end(), mime_type_data.begin(), mime_type_data.end());

  // Add checksum
  result.push_back((metadata_.checksum >> 24) & 0xFF);
  result.push_back((metadata_.checksum >> 16) & 0xFF);
  result.push_back((metadata_.checksum >> 8) & 0xFF);
  result.push_back(metadata_.checksum & 0xFF);

  return result;
}

void FileMetadataMessage::deserialize(const std::vector<uint8_t>& data) {
  size_t pos = 0;

  // Extract filename
  metadata_.filename = deserialize_string(data, pos);

  // Extract filesize
  if (pos + 8 > data.size()) {
    throw std::runtime_error("Not enough data to deserialize filesize");
  }
  metadata_.filesize =
      (static_cast<uint64_t>(data[pos]) << 56) | (static_cast<uint64_t>(data[pos + 1]) << 48) |
      (static_cast<uint64_t>(data[pos + 2]) << 40) | (static_cast<uint64_t>(data[pos + 3]) << 32) |
      (static_cast<uint64_t>(data[pos + 4]) << 24) | (static_cast<uint64_t>(data[pos + 5]) << 16) |
      (static_cast<uint64_t>(data[pos + 6]) << 8) | static_cast<uint64_t>(data[pos + 7]);
  pos += 8;

  // Extract block_size
  if (pos + 4 > data.size()) {
    throw std::runtime_error("Not enough data to deserialize block_size");
  }
  metadata_.block_size =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  // Extract total_blocks
  if (pos + 4 > data.size()) {
    throw std::runtime_error("Not enough data to deserialize total_blocks");
  }
  metadata_.total_blocks =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  // Extract mime_type
  metadata_.mime_type = deserialize_string(data, pos);

  // Extract checksum
  if (pos + 4 > data.size()) {
    throw std::runtime_error("Not enough data to deserialize checksum");
  }
  metadata_.checksum =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;
}

// FileBlockMessage implementation
std::vector<uint8_t> FileBlockMessage::serialize() const {
  std::vector<uint8_t> result;

  // Add block_index
  result.push_back((block_index_ >> 24) & 0xFF);
  result.push_back((block_index_ >> 16) & 0xFF);
  result.push_back((block_index_ >> 8) & 0xFF);
  result.push_back(block_index_ & 0xFF);

  // Add block_data size
  uint32_t data_size = static_cast<uint32_t>(block_data_.size());
  result.push_back((data_size >> 24) & 0xFF);
  result.push_back((data_size >> 16) & 0xFF);
  result.push_back((data_size >> 8) & 0xFF);
  result.push_back(data_size & 0xFF);

  // Add block_data
  result.insert(result.end(), block_data_.begin(), block_data_.end());

  // Add checksum
  result.push_back((checksum_ >> 24) & 0xFF);
  result.push_back((checksum_ >> 16) & 0xFF);
  result.push_back((checksum_ >> 8) & 0xFF);
  result.push_back(checksum_ & 0xFF);

  return result;
}

void FileBlockMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() < 12) {  // 4 (index) + 4 (size) + 4 (checksum)
    throw std::runtime_error("Invalid FileBlockMessage data size");
  }

  size_t pos = 0;

  // Extract block_index
  block_index_ = (static_cast<uint32_t>(data[pos]) << 24) |
                 (static_cast<uint32_t>(data[pos + 1]) << 16) |
                 (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  // Extract block_data size
  uint32_t data_size =
      (static_cast<uint32_t>(data[pos]) << 24) | (static_cast<uint32_t>(data[pos + 1]) << 16) |
      (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
  pos += 4;

  if (pos + data_size + 4 > data.size()) {
    throw std::runtime_error("Invalid block data size in FileBlockMessage");
  }

  // Extract block_data
  block_data_.assign(data.begin() + pos, data.begin() + pos + data_size);
  pos += data_size;

  // Extract checksum
  checksum_ = (static_cast<uint32_t>(data[pos]) << 24) |
              (static_cast<uint32_t>(data[pos + 1]) << 16) |
              (static_cast<uint32_t>(data[pos + 2]) << 8) | static_cast<uint32_t>(data[pos + 3]);
}

// BlockAckMessage implementation
std::vector<uint8_t> BlockAckMessage::serialize() const {
  std::vector<uint8_t> result(5);

  // Add block_index
  result[0] = (block_index_ >> 24) & 0xFF;
  result[1] = (block_index_ >> 16) & 0xFF;
  result[2] = (block_index_ >> 8) & 0xFF;
  result[3] = block_index_ & 0xFF;

  // Add success flag
  result[4] = success_ ? 1 : 0;

  return result;
}

void BlockAckMessage::deserialize(const std::vector<uint8_t>& data) {
  if (data.size() != 5) {
    throw std::runtime_error("Invalid BlockAckMessage data size");
  }

  // Extract block_index
  block_index_ = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                 (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);

  // Extract success flag
  success_ = (data[4] != 0);
}

// Message factory implementation
std::unique_ptr<Message> create_message(MessageType type) {
  switch (type) {
    case MessageType::SERVER_HELLO:
      return std::make_unique<ServerHelloMessage>();
    case MessageType::CLIENT_HELLO:
      return std::make_unique<ClientHelloMessage>();
    case MessageType::CLIENT_AUTH:
      return std::make_unique<ClientAuthMessage>();
    case MessageType::SERVER_AUTH:
      return std::make_unique<ServerAuthMessage>();
    case MessageType::SESSION_KEY:
      return std::make_unique<SessionKeyMessage>();
    case MessageType::SESSION_CONFIRM:
      return std::make_unique<SessionConfirmMessage>();
    case MessageType::FILE_METADATA:
      return std::make_unique<FileMetadataMessage>();
    case MessageType::FILE_BLOCK:
      return std::make_unique<FileBlockMessage>();
    case MessageType::BLOCK_ACK:
      return std::make_unique<BlockAckMessage>();
    case MessageType::ERROR_MSG:
      // Handle error messages if defined in your protocol
      // return std::make_unique<ErrorMessage>();
      return nullptr;
    default:
      return nullptr;
  }
}

// Parse a complete message from raw data
std::unique_ptr<Message> parse_message(const std::vector<uint8_t>& data) {
  if (data.size() < 5) {  // 4 (size) + 1 (type) minimum
    throw std::runtime_error("Message data too small to parse");
  }

  // Extract message size and type
  uint32_t size = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
                  (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);

  MessageType type = static_cast<MessageType>(data[4]);

  if (data.size() != size + 5) {
    throw std::runtime_error("Message data size doesn't match header");
  }

  // Create message of the appropriate type
  std::unique_ptr<Message> message = create_message(type);
  if (!message) {
    throw std::runtime_error("Unknown message type");
  }

  // Deserialize message data (skip header)
  message->deserialize(std::vector<uint8_t>(data.begin() + 5, data.end()));

  return message;
}

}  // namespace protocol
}  // namespace stx