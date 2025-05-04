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

class ServerSessionTest : public Test {
 protected:
  void SetUp() override {
    // Initialize crypto subsystem
    stx::crypto::initialize();
  }

  void TearDown() override { stx::crypto::cleanup(); }
};

// Test 1: Constructor with closed socket
TEST_F(ServerSessionTest, ConstructorWithClosedSocket) {
  auto mock_socket = std::make_shared<MockSocket>();

  // The constructor checks socket && socket->is_open()
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(false));

  ServerSession session(mock_socket);

  // is_active() should return false without checking socket again
  // because active_ was set to false in constructor
  EXPECT_FALSE(session.is_active());
}

// Test 2: Constructor with null socket
TEST_F(ServerSessionTest, ConstructorWithNullSocket) {
  ServerSession session(nullptr);
  EXPECT_FALSE(session.is_active());
}

// Test 3: Send message - testing write_to_socket behavior
TEST_F(ServerSessionTest, SendMessageWriteHeaderAndBody) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

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
TEST_F(ServerSessionTest, SendMessageHeaderFailure) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

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
TEST_F(ServerSessionTest, ReceiveMessageSuccess) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

  // Prepare a ClientHelloMessage data
  std::string client_id = "test_client";
  stx::crypto::Nonce client_nonce{};

  // Serialize the actual message to get the correct data
  ClientHelloMessage temp_msg(client_id, client_nonce);
  std::vector<uint8_t> body = temp_msg.serialize();

  // Create header
  std::vector<uint8_t> header(5);
  uint32_t size = static_cast<uint32_t>(body.size());
  header[0] = (size >> 24) & 0xFF;
  header[1] = (size >> 16) & 0xFF;
  header[2] = (size >> 8) & 0xFF;
  header[3] = size & 0xFF;
  header[4] = static_cast<uint8_t>(MessageType::CLIENT_HELLO);

  // Mock reading header (5 bytes)
  EXPECT_CALL(*mock_socket, read_some(_, _))
      .WillOnce(Invoke([&header](asio::mutable_buffer buffer, asio::error_code& ec) {
        EXPECT_EQ(buffer.size(), 5);
        ec = asio::error_code();
        memcpy(buffer.data(), header.data(), header.size());
        return 5;
      }))
      // Mock reading body
      .WillOnce(Invoke([&body](asio::mutable_buffer buffer, asio::error_code& ec) {
        EXPECT_EQ(buffer.size(), body.size());
        ec = asio::error_code();
        memcpy(buffer.data(), body.data(), body.size());
        return body.size();
      }));

  auto received = session.receive_message();
  ASSERT_NE(received, nullptr);
  EXPECT_EQ(received->type(), MessageType::CLIENT_HELLO);

  ClientHelloMessage* client_hello = dynamic_cast<ClientHelloMessage*>(received.get());
  ASSERT_NE(client_hello, nullptr);
  EXPECT_EQ(client_hello->client_id(), client_id);
}

// Test 6: Receive message with connection error
TEST_F(ServerSessionTest, ReceiveMessageConnectionError) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

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

// Test 7: Server cannot do client handshake
TEST_F(ServerSessionTest, ClientHandshakeNotAllowed) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

  // Server should not be able to do client handshake
  bool result = session.client_handshake();
  EXPECT_FALSE(result);
}

// Test 8: Server cannot send files
TEST_F(ServerSessionTest, SendFileNotAllowed) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

  // Server should not be able to send files
  bool result = session.send_file("test_file.txt");
  EXPECT_FALSE(result);
}

// Test 9: Simple server handshake - just test the flow
TEST_F(ServerSessionTest, ServerHandshakeBasicFlow) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

  // For handshake, we expect:
  // 1. Send ServerHello
  // 2. Receive ClientHello
  // 3. Receive ClientAuth
  // 4. Send ServerAuth
  // 5. Receive SessionKey
  // 6. Send SessionConfirm

  // 1. Send ServerHello
  EXPECT_CALL(*mock_socket, send(_))
      .WillOnce(Return(5))    // Header
      .WillOnce(Return(16));  // Nonce

  // Mock the rest of the handshake to fail early
  EXPECT_CALL(*mock_socket, read_some(_, _))
      .WillOnce(Invoke([](asio::mutable_buffer buffer, asio::error_code& ec) {
        ec = asio::error::connection_reset;
        (void)buffer;  // to avoid warning about unused variable
        return 0;
      }));

  bool result = session.server_handshake();
  EXPECT_FALSE(result);
}

// Test 10: Basic receive file test
TEST_F(ServerSessionTest, ReceiveFileBasicFlow) {
  auto mock_socket = std::make_shared<MockSocket>();

  // Constructor check
  EXPECT_CALL(*mock_socket, is_open()).WillOnce(Return(true));

  ServerSession session(mock_socket);

  // For receive file, we first expect to receive FileMetadata
  // but we'll simulate connection drop
  EXPECT_CALL(*mock_socket, read_some(_, _))
      .WillOnce(Invoke([](asio::mutable_buffer buffer, asio::error_code& ec) {
        ec = asio::error::connection_reset;
        (void)buffer;  // to avoid warning about unused variable
        return 0;
      }));

  bool result = session.receive_file("./test_dir");
  EXPECT_FALSE(result);
}