// include/stx/crypto.h
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace stx {
namespace crypto {

constexpr size_t KEY_SIZE = 32;         // 256 bits
constexpr size_t IV_SIZE = 12;          // 96 bits for GCM
constexpr size_t AUTH_TAG_SIZE = 16;    // 128 bits
constexpr size_t NONCE_SIZE = 16;       // 128 bits
constexpr size_t SESSION_ID_SIZE = 16;  // 128 bits

using Key = std::array<uint8_t, KEY_SIZE>;
using IV = std::array<uint8_t, IV_SIZE>;
using AuthTag = std::array<uint8_t, AUTH_TAG_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using SessionId = std::array<uint8_t, SESSION_ID_SIZE>;

// Initialize OpenSSL once
bool initialize();

// Clean up OpenSSL resources
void cleanup();

// Generate a random nonce
Nonce generate_nonce();

// Generate a random session ID
SessionId generate_session_id();

// Generate a random key
Key generate_key();

// Generate a random IV
IV generate_iv();

// Derive a session key from nonces and pre-shared key
Key derive_session_key(const Key& pre_shared_key, const Nonce& client_nonce,
                       const Nonce& server_nonce);

// Compute HMAC for authentication
std::vector<uint8_t> compute_hmac(const Key& key, const std::vector<uint8_t>& data);

// Verify HMAC
bool verify_hmac(const Key& key, const std::vector<uint8_t>& data,
                 const std::vector<uint8_t>& expected_hmac);

// Encrypt data using AES-256-GCM
std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const Key& key, const IV& iv,
                             AuthTag& auth_tag);

// Decrypt data using AES-256-GCM
std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const Key& key, const IV& iv,
                             const AuthTag& auth_tag);

// Calculate CRC32 checksum
uint32_t calculate_crc32(const std::vector<uint8_t>& data);

// Read pre-shared key from file or environment
Key get_preshared_key();

}  // namespace crypto
}  // namespace stx