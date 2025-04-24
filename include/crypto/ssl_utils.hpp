#pragma once

#include <asio/ssl/context.hpp>
#include <memory>
#include <string>


namespace stx::crypto {

/**
 * @brief Create and configure an SSL context for the server.
 * @param cert_file Path to the server certificate file.
 * @param key_file Path to the private key file.
 * @param dh_file Optional path to the DH parameters file.
 * @return Shared pointer to the configured SSL context.
 */
std::shared_ptr<asio::ssl::context> createServerSSLContext(const std::string& cert_file,
                                                           const std::string& key_file,
                                                           const std::string& dh_file = "");

}  // namespace stx::crypto
