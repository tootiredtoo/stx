#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>

namespace stx::network {

class TcpServer {
 public:
  TcpServer(asio::io_context& io_context, unsigned short port,
            std::shared_ptr<asio::ssl::context> ssl_context);
  void startAccept();

 private:
  void handleAccept(std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket,
                    const asio::error_code& error);

  asio::io_context& io_context_;
  asio::ssl::context& ssl_context_;
  asio::ip::tcp::acceptor acceptor_;
};

}  // namespace stx::network
