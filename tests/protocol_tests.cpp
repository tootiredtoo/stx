// tests/test_protocol.cpp
#include <cassert>
#include <iostream>
#include <string>
#include "stx/protocol.h"


// Helper function to print test results
void print_result(const std::string& test_name, bool success) {
  std::cout << test_name << ": " << (success ? "PASS" : "FAIL") << std::endl;
}

// Test message serialization and deserialization
bool test_message_serialization() {
  // Initialize crypto
  stx::crypto::initialize();

  // Test ServerHelloMessage
  stx::crypto::Nonce server_nonce = stx::crypto::generate_nonce();
  stx::protocol::ServerHelloMessage server_hello(server_nonce);
  std::vector<uint8_t> server_hello_data = server_hello.serialize();

  stx::protocol::ServerHelloMessage server_hello_deserialized;
  server_hello_deserialized.deserialize(server_hello_data);

  bool server_hello_ok = (server_nonce == server_hello_deserialized.server_nonce());

  // Test ClientHelloMessage
  stx::crypto::Nonce client_nonce = stx::crypto::generate_nonce();
  stx::protocol::ClientHelloMessage client_hello(client_nonce);
  std::vector<uint8_t> client_hello_data = client_hello.serialize();

  stx::protocol::ClientHelloMessage client_hello_deserialized;
  client_hello_deserialized.deserialize(client_hello_data);

  bool client_hello_ok = (client_nonce == client_hello_deserialized.client_nonce());

  // Test FileMetadataMessage
  stx::protocol::FileMetadata metadata;
  metadata.filename = "test_file.bin";
  metadata.filesize = 1024;
  metadata.block_size = 128;
  metadata.total_blocks = 8;
  metadata.mime_type = "application/octet-stream";
  metadata.checksum = 0x12345678;

  stx::protocol::FileMetadataMessage metadata_msg(metadata);
  std::vector<uint8_t> metadata_data = metadata_msg.serialize();

  stx::protocol::FileMetadataMessage metadata_msg_deserialized;
  metadata_msg_deserialized.deserialize(metadata_data);

  const stx::protocol::FileMetadata& deserialized_metadata = metadata_msg_deserialized.metadata();

  bool metadata_ok = (metadata.filename == deserialized_metadata.filename) &&
                     (metadata.filesize == deserialized_metadata.filesize) &&
                     (metadata.block_size == deserialized_metadata.block_size) &&
                     (metadata.total_blocks == deserialized_metadata.total_blocks) &&
                     (metadata.mime_type == deserialized_metadata.mime_type) &&
                     (metadata.checksum == deserialized_metadata.checksum);

  // Test FileBlockMessage
  uint32_t block_index = 42;
  std::vector<uint8_t> block_data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  uint32_t block_checksum = stx::crypto::calculate_crc32(block_data);

  stx::protocol::FileBlockMessage block_msg(block_index, block_data, block_checksum);
  std::vector<uint8_t> block_data_serialized = block_msg.serialize();

  stx::protocol::FileBlockMessage block_msg_deserialized;
  block_msg_deserialized.deserialize(block_data_serialized);

  bool block_ok = (block_index == block_msg_deserialized.block_index()) &&
                  (block_data == block_msg_deserialized.block_data()) &&
                  (block_checksum == block_msg_deserialized.checksum());

  // Test message factory
  auto message = stx::protocol::create_message(stx::protocol::MessageType::SERVER_HELLO);
  bool factory_ok =
      (message != nullptr) && (message->type() == stx::protocol::MessageType::SERVER_HELLO);

  // Clean up
  stx::crypto::cleanup();

  return server_hello_ok && client_hello_ok && metadata_ok && block_ok && factory_ok;
}

int main() {
  // Run tests
  print_result("Message Serialization/Deserialization", test_message_serialization());

  return 0;
}
