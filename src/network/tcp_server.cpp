#include "network/tcp_server.hpp"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>

namespace stx::network {

TcpServer::TcpServer(asio::io_context& io_context, unsigned short port,
                     std::shared_ptr<asio::ssl::context> ssl_context)
    : io_context_(io_context),
      ssl_context_(*ssl_context),
      acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)) {}

void TcpServer::startAccept() {
  auto socket =
      std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(io_context_, ssl_context_);
  acceptor_.async_accept(socket->lowest_layer(), [this, socket](const asio::error_code& error) {
    handleAccept(socket, error);
  });
}

void TcpServer::handleAccept(std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket,
                             const asio::error_code& error) {
  if (error) {
    std::cerr << "Accept failed: " << error.message() << std::endl;
    return;
  }

  socket->async_handshake(asio::ssl::stream_base::server,
                          [this, socket](const asio::error_code& error) {
                            if (!error) {
                              std::cout << "Handshake successful!" << std::endl;
                              readData(socket);
                            } else {
                              std::cerr << "SSL Handshake failed: " << error.message() << std::endl;
                            }
                          });
}

void TcpServer::readData(std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket) {
  auto buffer = std::make_shared<std::vector<char>>(1024);
  socket->async_read_some(
      asio::buffer(*buffer),
      [this, socket, buffer](const asio::error_code& error, std::size_t bytes_transferred) {
        if (!error) {
          std::string received_data(buffer->begin(), buffer->begin() + bytes_transferred);
          std::cout << "Received: " << received_data << std::endl;

          writeData(socket, "Hello from server!");
        } else {
          std::cerr << "Read failed: " << error.message() << std::endl;
        }
      });
}

void TcpServer::writeData(std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket,
                          const std::string& message) {
  socket->async_write_some(
      asio::buffer(message),
      [this, socket, message](const asio::error_code& error, std::size_t /*bytes_transferred*/) {
        if (error) {
          std::cerr << "Write failed: " << error.message() << std::endl;
          return;
        }

        std::cout << "Sent message: " << message << std::endl;

        socket->async_shutdown([socket](const asio::error_code& error) {
          if (error) {
            std::cerr << "Shutdown failed: " << error.message() << std::endl;
          } else {
            std::cout << "Connection gracefully shut down" << std::endl;
          }
        });
      });
}

}  // namespace stx::network
