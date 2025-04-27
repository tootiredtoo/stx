#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include "crypto/crypto.hpp"
#include "protocols/protocol.hpp"
#include "protocols/socket.hpp"

// Custom matcher for asio::const_buffer
MATCHER_P(AsioBufferEq, expected, "Buffer equality") {
  const uint8_t* data = static_cast<const uint8_t*>(arg.data());
  size_t size = arg.size();

  if (size != expected.size()) return false;

  return std::equal(data, data + size, expected.begin());
}

// Simple matcher for any mutable buffer
MATCHER(AsioMutableBufferAnySize, "Buffer of any size") {
  return arg.size() > 0;  // Just check that it's a valid buffer
}

// Matcher for specific size mutable buffer
MATCHER_P(AsioMutableBufferOfSize, expected_size, "Buffer of specific size") {
  // Explicitly convert both to size_t to ensure we're comparing the same type
  size_t actual_size = arg.size();
  size_t expected = static_cast<size_t>(expected_size);
  return actual_size == expected;
}

namespace stx {
namespace protocol {

class MockSocket : public ISocket {
 public:
  MOCK_METHOD(bool, is_open, (), (const, override));
  MOCK_METHOD(void, close, (), (override));
  MOCK_METHOD(void, close, (asio::error_code & ec), (override));
  MOCK_METHOD(void, async_send,
              (const asio::const_buffer& buffer,
               std::function<void(const asio::error_code&, std::size_t)> handler),
              (override));
  MOCK_METHOD(void, async_receive,
              (asio::mutable_buffer buffer,
               std::function<void(const asio::error_code&, std::size_t)> handler),
              (override));
  MOCK_METHOD(std::size_t, send, (const asio::const_buffer& buffer), (override));
  MOCK_METHOD(std::size_t, receive, (asio::mutable_buffer buffer), (override));
  MOCK_METHOD(void, shutdown, (asio::ip::tcp::socket::shutdown_type what, asio::error_code& ec),
              (override));
  MOCK_METHOD(std::size_t, read_some, (asio::mutable_buffer buffer, asio::error_code& ec),
              (override));
};

// Test fixture for ClientSession
class ClientSessionTest : public ::testing::Test {
 protected:
  std::shared_ptr<MockSocket> mock_socket;
  std::unique_ptr<ClientSession> client_session;

  void SetUp() override {
    mock_socket = std::make_shared<MockSocket>();
    ON_CALL(*mock_socket, is_open()).WillByDefault(::testing::Return(true));
    client_session = std::make_unique<ClientSession>(mock_socket);

    // Initialize crypto subsystem
    stx::crypto::initialize();
  }

  void TearDown() override {
    client_session.reset();
    mock_socket.reset();
    stx::crypto::cleanup();
  }

  // Helper to set up a sequence of mocked reads
  void ExpectSocketReads(const std::vector<std::vector<uint8_t>>& chunks) {
    testing::InSequence seq;

    for (const auto& chunk : chunks) {
      EXPECT_CALL(*mock_socket, read_some(AsioMutableBufferOfSize(1024), testing::_))
          .WillOnce(testing::DoAll(
              testing::Invoke([chunk](asio::mutable_buffer buffer, asio::error_code& ec) {
                ec = asio::error_code();  // No error
                uint8_t* dest = static_cast<uint8_t*>(buffer.data());
                std::copy(chunk.begin(), chunk.end(), dest);
                return chunk.size();
              }),
              testing::Return(chunk.size())));
    }
  }
};

// Test case for ClientSession constructor
TEST_F(ClientSessionTest, Constructor) {
  EXPECT_TRUE(client_session->is_active());
}

// Test case for ClientSession close
TEST_F(ClientSessionTest, Close) {
  EXPECT_CALL(*mock_socket, shutdown(testing::_, testing::_));
  EXPECT_CALL(*mock_socket, close(testing::_));
  client_session->close();
  EXPECT_FALSE(client_session->is_active());
}

// Test case for is_active
TEST_F(ClientSessionTest, IsActive) {
  EXPECT_TRUE(client_session->is_active());

  // When socket reports it's closed
  ON_CALL(*mock_socket, is_open()).WillByDefault(::testing::Return(false));
  EXPECT_FALSE(client_session->is_active());
}

// Test case for send_message successful
TEST_F(ClientSessionTest, SendMessageSuccess) {
  // Create a test message (ServerHelloMessage)
  stx::crypto::Nonce nonce{};
  ServerHelloMessage test_message(nonce);

  // Expected serialized message with header
  std::vector<uint8_t> serialized = test_message.serialize();

  // Header: 4 bytes for size + 1 byte for type
  std::vector<uint8_t> expected;
  uint32_t size = static_cast<uint32_t>(serialized.size());
  expected.push_back((size >> 24) & 0xFF);
  expected.push_back((size >> 16) & 0xFF);
  expected.push_back((size >> 8) & 0xFF);
  expected.push_back(size & 0xFF);
  expected.push_back(static_cast<uint8_t>(MessageType::SERVER_HELLO));

  // Append serialized body
  expected.insert(expected.end(), serialized.begin(), serialized.end());

  // Expect the send call with our expected data
  EXPECT_CALL(*mock_socket, send(AsioBufferEq(expected)))
      .WillOnce(testing::Return(expected.size()));

  // Call the method
  bool result = client_session->send_message(test_message);

  // Verify result
  EXPECT_TRUE(result);
  EXPECT_TRUE(client_session->is_active());
}

// Test case for send_message failure
TEST_F(ClientSessionTest, SendMessageFailure) {
  // Create a test message
  stx::crypto::Nonce nonce{};
  ServerHelloMessage test_message(nonce);

  // Expect the send call to fail
  EXPECT_CALL(*mock_socket, send(testing::_))
      .WillOnce(testing::Throw(std::runtime_error("Simulated network error")));

  // Call the method
  bool result = client_session->send_message(test_message);

  // Verify result
  EXPECT_FALSE(result);
  EXPECT_FALSE(client_session->is_active());
}

// Test case for receive_message success
TEST_F(ClientSessionTest, ReceiveMessageSuccess) {
  // Create sample data for a ServerHelloMessage
  stx::crypto::Nonce nonce{};
  for (size_t i = 0; i < nonce.size(); i++) {
    nonce[i] = static_cast<uint8_t>(i & 0xFF);
  }

  ServerHelloMessage original(nonce);
  std::vector<uint8_t> serialized_body = original.serialize();

  // Create the message header (4 bytes size + 1 byte type)
  std::vector<uint8_t> header(5);
  uint32_t size = static_cast<uint32_t>(serialized_body.size());
  header[0] = (size >> 24) & 0xFF;
  header[1] = (size >> 16) & 0xFF;
  header[2] = (size >> 8) & 0xFF;
  header[3] = size & 0xFF;
  header[4] = static_cast<uint8_t>(MessageType::SERVER_HELLO);

  // Set up read expectations - first header, then body
  ExpectSocketReads({header, serialized_body});

  // Call the method
  std::unique_ptr<Message> received = client_session->receive_message();

  // Verify result
  ASSERT_NE(received, nullptr);
  EXPECT_EQ(received->type(), MessageType::SERVER_HELLO);

  // Cast and verify the specific message contents
  ServerHelloMessage* server_hello = dynamic_cast<ServerHelloMessage*>(received.get());
  ASSERT_NE(server_hello, nullptr);
  EXPECT_EQ(server_hello->server_nonce(), nonce);
}

// Test case for receive_message failure
TEST_F(ClientSessionTest, ReceiveMessageFailure) {
  // Expect the read call to fail
  EXPECT_CALL(*mock_socket, read_some(testing::_, testing::_))
      .WillOnce(testing::DoAll(testing::SetArgReferee<1>(asio::error::connection_reset),
                               testing::Return(0)));

  // Call the method
  std::unique_ptr<Message> received = client_session->receive_message();

  // Verify result
  EXPECT_EQ(received, nullptr);
  EXPECT_FALSE(client_session->is_active());
}

// Test case for client_handshake
TEST_F(ClientSessionTest, ClientHandshake) {
  // This would be a more complex test involving multiple message exchanges
  // For now, we'll just verify the basic structure

  // Mock ServerHello message reception
  stx::crypto::Nonce server_nonce{};
  ServerHelloMessage server_hello(server_nonce);
  std::vector<uint8_t> server_hello_serialized = server_hello.serialize();

  std::vector<uint8_t> server_hello_header(5);
  uint32_t size = static_cast<uint32_t>(server_hello_serialized.size());
  server_hello_header[0] = (size >> 24) & 0xFF;
  server_hello_header[1] = (size >> 16) & 0xFF;
  server_hello_header[2] = (size >> 8) & 0xFF;
  server_hello_header[3] = size & 0xFF;
  server_hello_header[4] = static_cast<uint8_t>(MessageType::SERVER_HELLO);

  // Mock subsequent interactions - this is simplified; actual test would be more complex
  // We'll expect initial ServerHello read, then simulate failure in next step
  EXPECT_CALL(*mock_socket, read_some(testing::_, testing::_))
      .WillOnce(
          testing::DoAll(testing::Invoke([&](asio::mutable_buffer buffer, asio::error_code& ec) {
                           ec = asio::error_code();  // No error
                           uint8_t* dest = static_cast<uint8_t*>(buffer.data());
                           std::copy(server_hello_header.begin(), server_hello_header.end(), dest);
                           return server_hello_header.size();
                         }),
                         testing::Return(server_hello_header.size())))
      .WillOnce(testing::DoAll(
          testing::Invoke([&](asio::mutable_buffer buffer, asio::error_code& ec) {
            ec = asio::error_code();  // No error
            uint8_t* dest = static_cast<uint8_t*>(buffer.data());
            std::copy(server_hello_serialized.begin(), server_hello_serialized.end(), dest);
            return server_hello_serialized.size();
          }),
          testing::Return(server_hello_serialized.size())))
      .WillRepeatedly(testing::DoAll(testing::SetArgReferee<1>(asio::error::connection_reset),
                                     testing::Return(0)));

  // Call the handshake method
  bool result = client_session->client_handshake("test_client");

  // We expect failure since we're not fully mocking the handshake sequence
  EXPECT_FALSE(result);
}

}  // namespace protocol
}  // namespace stx