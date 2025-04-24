#include "crypto/ssl_utils.hpp"
#include <asio/ssl/context.hpp>

namespace stx::crypto {

std::shared_ptr<asio::ssl::context> createServerSSLContext(const std::string& cert_file,
                                                           const std::string& key_file,
                                                           const std::string& dh_file) {
  auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tlsv12_server);

  ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                   asio::ssl::context::single_dh_use);

  ctx->use_certificate_chain_file(cert_file);
  ctx->use_private_key_file(key_file, asio::ssl::context::pem);

  if (!dh_file.empty()) {
    ctx->use_tmp_dh_file(dh_file);
  }

  return ctx;
}

}  // namespace stx::crypto
