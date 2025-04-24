#pragma once

#include <asio/ssl/context.hpp>
#include <memory>
#include <string>

namespace stx::network {

/**
 * @brief Creates and configures an SSL context for use in a secure server.
 *
 * @param cert_file Path to the server certificate file (PEM format).
 * @param key_file Path to the server private key file (PEM format).
 * @return Shared pointer to the configured asio::ssl::context.
 *
 * @throws std::runtime_error if setup fails.
 */
std::shared_ptr<asio::ssl::context> create_ssl_context(const std::string& cert_file,
                                                       const std::string& key_file);

}  // namespace stx::network
