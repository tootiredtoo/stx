#include "network/tcp_server.hpp"
#include <iostream>

namespace stx::network {

TcpServer::TcpServer(asio::io_context& io_context, unsigned short port,
                     std::shared_ptr<asio::ssl::context> ssl_context)
    : io_context_(io_context),
      ssl_context_(*ssl_context),
      acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {}

void TcpServer::startAccept() {
  auto socket = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(acceptor_.get_executor(),
                                                                           ssl_context_);
  acceptor_.async_accept(socket->lowest_layer(), [this, socket](const asio::error_code& error) {
    handleAccept(socket, error);
  });
}

void TcpServer::handleAccept(std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket,
                             const asio::error_code& error) {
  if (!error) {
    socket->async_handshake(
        asio::ssl::stream_base::server, [this, socket](const asio::error_code& handshake_error) {
          if (!handshake_error) {
            // Successfully accepted connection, handle the communication here
            std::cout << "Connection established!" << std::endl;
            // You can start reading or writing to the socket here
          } else {
            std::cerr << "Handshake failed: " << handshake_error.message() << std::endl;
          }
        });
  } else {
    std::cerr << "Accept failed: " << error.message() << std::endl;
  }
}

}  // namespace stx::network
