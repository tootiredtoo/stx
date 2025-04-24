#include "network/ssl_utils.hpp"
#include <asio/ssl/context.hpp>
#include <iostream>
#include <stdexcept>

namespace stx::network {

std::shared_ptr<asio::ssl::context> create_ssl_context(const std::string& cert_file,
                                                       const std::string& key_file) {
  auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tlsv12_server);

  try {
    ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                     asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 |
                     asio::ssl::context::no_tlsv1_1 | asio::ssl::context::single_dh_use);

    ctx->use_certificate_chain_file(cert_file);
    ctx->use_private_key_file(key_file, asio::ssl::context::pem);
  } catch (const std::exception& e) {
    std::cerr << "[SSL Setup Error] " << e.what() << std::endl;
    throw;
  }

  return ctx;
}

}  // namespace stx::network
