#include <asio/io_context.hpp>
#include <iostream>
#include "network/ssl_utils.hpp"
#include "network/tcp_server.hpp"


int main() {
  try {
    asio::io_context io;

    auto ssl_ctx = stx::network::create_ssl_context("certs/cert.pem", "certs/key.pem");
    stx::network::TcpServer server(io, 4433, ssl_ctx);

    server.startAccept();

    io.run();
  } catch (const std::exception& ex) {
    std::cerr << "[Fatal] Exception: " << ex.what() << std::endl;
    return 1;
  }

  return 0;
}
