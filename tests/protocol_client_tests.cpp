#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <asio.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "crypto/crypto.hpp"
#include "protocols/protocol.hpp"
#include "protocols/socket.hpp"

using namespace stx::protocol;
using namespace testing;

// Mock Socket class
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

class ClientSessionTest : public Test {
 protected:
  void SetUp() override {
    // Initialize crypto subsystem
    stx::crypto::initialize();
  }

  void TearDown() override { stx::crypto::cleanup(); }
};

// Test 1: Constructor with closed socket
TEST_F(ClientSessionTest, ConstructorWithClosedSocket) {
  auto mock_socket = std::make_shared<MockSocket>();

  // The constructor checks socket && socket->is_open()
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(false));

  ClientSession session(mock_socket);

  // is_active() should return false without checking socket again
  // because active_ was set to false in constructor
  EXPECT_FALSE(session.is_active());
}

// Test 2: Constructor with null socket
TEST_F(ClientSessionTest, ConstructorWithNullSocket) {
  ClientSession session(nullptr);
  EXPECT_FALSE(session.is_active());
}

// Test 3: Send message - testing write_to_socket behavior
TEST_F(ClientSessionTest, SendMessageWriteHeaderAndBody) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Create a simple message
  stx::crypto::Nonce nonce{};
  ServerHelloMessage message(nonce);

  // The send_message will call send twice (header and body)
  // First for the 5-byte header
  EXPECT_CALL(*mock_socket, send(_))
      .WillOnce(Invoke([](const asio::const_buffer& buffer) {
        EXPECT_EQ(buffer.size(), 5);  // Header size
        return 5;                     // Return the number of bytes sent
      }))
      // Then for the message body (16 bytes for nonce)
      .WillOnce(Invoke([](const asio::const_buffer& buffer) {
        EXPECT_EQ(buffer.size(), 16);  // Nonce size
        return 16;                     // Return the number of bytes sent
      }));

  bool result = session.send_message(message);
  EXPECT_TRUE(result);
}

// Test 4: Send message failure on header
TEST_F(ClientSessionTest, SendMessageHeaderFailure) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Create a simple message
  stx::crypto::Nonce nonce{};
  ServerHelloMessage message(nonce);

  // Fail on sending header - return 0 bytes sent
  EXPECT_CALL(*mock_socket, send(_)).WillOnce(Return(0));

  bool result = session.send_message(message);
  EXPECT_FALSE(result);

  // Session should be marked as inactive
  EXPECT_FALSE(session.is_active());
}

// Test 5: Receive message with proper buffer sizes
TEST_F(ClientSessionTest, ReceiveMessageSuccess) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Prepare a ServerHelloMessage data
  std::vector<uint8_t> header(5);
  header[0] = 0;
  header[1] = 0;
  header[2] = 0;
  header[3] = 16;  // Size = 16
  header[4] = static_cast<uint8_t>(MessageType::SERVER_HELLO);

  std::vector<uint8_t> body(16, 0);  // Nonce data

  // Mock reading header (5 bytes)
  EXPECT_CALL(*mock_socket, read_some(_, _))
      .WillOnce(Invoke([&header](asio::mutable_buffer buffer, asio::error_code& ec) {
        EXPECT_EQ(buffer.size(), 5);
        ec = asio::error_code();
        memcpy(buffer.data(), header.data(), header.size());
        return 5;
      }))
      // Mock reading body (16 bytes)
      .WillOnce(Invoke([&body](asio::mutable_buffer buffer, asio::error_code& ec) {
        EXPECT_EQ(buffer.size(), 16);
        ec = asio::error_code();
        memcpy(buffer.data(), body.data(), body.size());
        return 16;
      }));

  auto received = session.receive_message();
  ASSERT_NE(received, nullptr);
  EXPECT_EQ(received->type(), MessageType::SERVER_HELLO);
}

// Test 6: Receive message with connection error
TEST_F(ClientSessionTest, ReceiveMessageConnectionError) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Mock reading header with error
  EXPECT_CALL(*mock_socket, read_some(_, _))
      .WillOnce(Invoke([](asio::mutable_buffer buffer, asio::error_code& ec) {
        ec = asio::error::connection_reset;
        (void)buffer;  // to avoid warning about unused variable
        return 0;
      }));

  auto received = session.receive_message();
  EXPECT_EQ(received, nullptr);
  EXPECT_FALSE(session.is_active());
}

// Test 7: Client cannot do server handshake
TEST_F(ClientSessionTest, ServerHandshakeNotAllowed) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Client should not be able to do server handshake
  bool result = session.server_handshake();
  EXPECT_FALSE(result);
}

// Test 8: Client cannot receive files directly
TEST_F(ClientSessionTest, ReceiveFileNotAllowed) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Client should not be able to receive files
  bool result = session.receive_file("./downloads");
  EXPECT_FALSE(result);
}

//  Test 9: Additional test to verify the actual send behavior
TEST_F(ClientSessionTest, SendMessageVerifyDataContent) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ClientSession session(mock_socket);

  // Create a simple message
  stx::crypto::Nonce nonce{};
  ServerHelloMessage message(nonce);

  // Capture what data is actually sent
  std::vector<uint8_t> captured_header;
  std::vector<uint8_t> captured_body;

  EXPECT_CALL(*mock_socket, send(_))
      .WillOnce(Invoke([&captured_header](const asio::const_buffer& buffer) {
        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        captured_header.assign(data, data + buffer.size());
        return buffer.size();
      }))
      .WillOnce(Invoke([&captured_body](const asio::const_buffer& buffer) {
        const uint8_t* data = static_cast<const uint8_t*>(buffer.data());
        captured_body.assign(data, data + buffer.size());
        return buffer.size();
      }));

  bool result = session.send_message(message);
  EXPECT_TRUE(result);

  // Verify header format
  EXPECT_EQ(captured_header.size(), 5);
  EXPECT_EQ(captured_header[4], static_cast<uint8_t>(MessageType::SERVER_HELLO));

  // Verify body
  EXPECT_EQ(captured_body.size(), 16);  // Nonce size
}