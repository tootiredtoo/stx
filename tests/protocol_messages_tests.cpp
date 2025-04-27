#include <gtest/gtest.h>
#include <numeric>
#include "protocols/protocol.hpp"

using namespace stx::protocol;

namespace {

template <typename T>
std::vector<uint8_t> corrupt_data(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> corrupted = data;
  if (!corrupted.empty()) {
    corrupted.pop_back();  // Remove last byte
  }
  return corrupted;
}

// === ServerHelloMessage ===
TEST(ServerHelloMessageTest, SerializeDeserialize) {
  stx::crypto::Nonce nonce{};
  std::iota(nonce.begin(), nonce.end(), 0);  // Fill with 0..n

  ServerHelloMessage original(nonce);
  auto data = original.serialize();

  ServerHelloMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.server_nonce(), copy.server_nonce());
}

TEST(ServerHelloMessageTest, DeserializeInvalidSize) {
  ServerHelloMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2, 3}), std::runtime_error);
}

// === ClientHelloMessage ===
TEST(ClientHelloMessageTest, SerializeDeserialize) {
  stx::crypto::Nonce nonce{};
  std::iota(nonce.begin(), nonce.end(), 0);

  std::string client_id = "TestClient";
  ClientHelloMessage original(client_id, nonce);
  auto data = original.serialize();

  ClientHelloMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.client_id(), copy.client_id());
  EXPECT_EQ(original.client_nonce(), copy.client_nonce());
}

TEST(ClientHelloMessageTest, DeserializeInvalidData) {
  ClientHelloMessage msg;
  EXPECT_THROW(msg.deserialize({0, 0, 0, 50}), std::runtime_error);  // ID length too big
}

// === ClientAuthMessage ===
TEST(ClientAuthMessageTest, SerializeDeserialize) {
  stx::crypto::Nonce client_nonce{}, server_nonce{};
  std::iota(client_nonce.begin(), client_nonce.end(), 0);
  std::iota(server_nonce.begin(), server_nonce.end(), 100);

  std::vector<uint8_t> hmac = {1, 2, 3, 4, 5};

  ClientAuthMessage original(client_nonce, server_nonce, hmac);
  auto data = original.serialize();

  ClientAuthMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.client_nonce(), copy.client_nonce());
  EXPECT_EQ(original.server_nonce(), copy.server_nonce());
  EXPECT_EQ(original.hmac(), copy.hmac());
}

TEST(ClientAuthMessageTest, DeserializeInvalidData) {
  ClientAuthMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2, 3}), std::runtime_error);  // Too small
}

// === ServerAuthMessage ===
TEST(ServerAuthMessageTest, SerializeDeserialize) {
  std::vector<uint8_t> hmac = {10, 20, 30};

  ServerAuthMessage original(hmac);
  auto data = original.serialize();

  ServerAuthMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.hmac(), copy.hmac());
}

TEST(ServerAuthMessageTest, DeserializeInvalidData) {
  ServerAuthMessage msg;
  EXPECT_THROW(msg.deserialize({0, 0, 0}), std::runtime_error);  // too short for size field
}

// === SessionKeyMessage ===
TEST(SessionKeyMessageTest, SerializeDeserialize) {
  stx::crypto::SessionId session_id{};
  stx::crypto::IV iv{};
  std::iota(session_id.begin(), session_id.end(), 1);
  std::iota(iv.begin(), iv.end(), 2);

  SessionKeyMessage original(session_id, iv);
  auto data = original.serialize();

  SessionKeyMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.session_id(), copy.session_id());
  EXPECT_EQ(original.iv(), copy.iv());
}

TEST(SessionKeyMessageTest, DeserializeInvalidData) {
  SessionKeyMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2, 3}), std::runtime_error);
}

// === SessionConfirmMessage ===
TEST(SessionConfirmMessageTest, SerializeDeserialize) {
  SessionConfirmMessage original(true);
  auto data = original.serialize();

  SessionConfirmMessage copy;
  copy.deserialize(data);

  EXPECT_TRUE(copy.success());
}

TEST(SessionConfirmMessageTest, DeserializeInvalidData) {
  SessionConfirmMessage msg;
  EXPECT_THROW(msg.deserialize({}), std::runtime_error);
}

// === FileMetadataMessage ===
TEST(FileMetadataMessageTest, SerializeDeserialize) {
  FileMetadata metadata{"example.txt", 1234567890, 4096, 300, "text/plain", 0xDEADBEEF};

  FileMetadataMessage original(metadata);
  auto data = original.serialize();

  FileMetadataMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.metadata().filename, copy.metadata().filename);
  EXPECT_EQ(original.metadata().filesize, copy.metadata().filesize);
  EXPECT_EQ(original.metadata().block_size, copy.metadata().block_size);
  EXPECT_EQ(original.metadata().total_blocks, copy.metadata().total_blocks);
  EXPECT_EQ(original.metadata().mime_type, copy.metadata().mime_type);
  EXPECT_EQ(original.metadata().checksum, copy.metadata().checksum);
}

TEST(FileMetadataMessageTest, DeserializeInvalidData) {
  FileMetadataMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2, 3}), std::runtime_error);
}

// === FileBlockMessage ===
TEST(FileBlockMessageTest, SerializeDeserialize) {
  std::vector<uint8_t> block_data = {1, 2, 3, 4, 5};

  FileBlockMessage original(42, block_data, 0xABCDEF12);
  auto data = original.serialize();

  FileBlockMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.block_index(), copy.block_index());
  EXPECT_EQ(original.block_data(), copy.block_data());
  EXPECT_EQ(original.checksum(), copy.checksum());
}

TEST(FileBlockMessageTest, DeserializeInvalidData) {
  FileBlockMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2}), std::runtime_error);
}

// === BlockAckMessage ===
TEST(BlockAckMessageTest, SerializeDeserialize) {
  BlockAckMessage original(777, true);
  auto data = original.serialize();

  BlockAckMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.block_index(), copy.block_index());
  EXPECT_EQ(original.success(), copy.success());
}

TEST(BlockAckMessageTest, DeserializeInvalidData) {
  BlockAckMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2}), std::runtime_error);
}

// === ResumeQueryMessage ===
TEST(ResumeQueryMessageTest, SerializeDeserialize) {
  ResumeQueryMessage original("resume.txt");
  auto data = original.serialize();

  ResumeQueryMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.filename(), copy.filename());
}

TEST(ResumeQueryMessageTest, DeserializeInvalidData) {
  ResumeQueryMessage msg;
  EXPECT_THROW(msg.deserialize({1, 2, 3}), std::runtime_error);
}

// === ResumeResponseMessage ===
TEST(ResumeResponseMessageTest, SerializeDeserialize) {
  ResumeResponseMessage original("resume.txt", 99);
  auto data = original.serialize();

  ResumeResponseMessage copy;
  copy.deserialize(data);

  EXPECT_EQ(original.filename(), copy.filename());
  EXPECT_EQ(original.last_block_received(), copy.last_block_received());
}

TEST(ResumeResponseMessageTest, DeserializeInvalidData) {
  ResumeResponseMessage msg;
  EXPECT_THROW(msg.deserialize({}), std::runtime_error);
}

}  // namespace
