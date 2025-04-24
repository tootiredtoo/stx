#include <asio/io_context.hpp>
#include <asio/ssl.hpp>
#include <iostream>
#include <memory>
#include <stdexcept>
#include "crypto/ssl_utils.hpp"
#include "network/tcp_server.hpp"

int main() {
  try {
    asio::io_context io_context;

    std::string cert_file = "certs/server.crt";
    std::string key_file = "certs/server.key";
    std::string dh_file = "certs/dh2048.pem";

    auto ssl_ctx = stx::crypto::createServerSSLContext(cert_file, key_file, dh_file);

    stx::network::TcpServer server(io_context, 443, ssl_ctx);
    server.startAccept();

    std::cout << "SSL Context successfully created!" << std::endl;

    io_context.run();

  } catch (const std::exception& e) {
    std::cerr << "[Error] Exception occurred: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "[Error] Unknown exception occurred!" << std::endl;
    return 1;
  }

  return 0;
}
