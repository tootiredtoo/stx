#include "crypto/crypto.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace stx {
namespace crypto {

namespace {
// Print OpenSSL error details
std::string get_openssl_error() {
  std::stringstream ss;
  unsigned long err = ERR_get_error();
  while (err) {
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    ss << "OpenSSL error: " << buf << std::endl;
    err = ERR_get_error();
  }
  return ss.str();
}
}  // namespace

bool initialize() {
  // Initialize OpenSSL
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  return RAND_poll() == 1;
}

void cleanup() {
  // Clean up OpenSSL resources
  EVP_cleanup();
  ERR_free_strings();
}

Nonce generate_nonce() {
  Nonce nonce;
  if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
    throw std::runtime_error("Failed to generate random nonce: " + get_openssl_error());
  }
  return nonce;
}

SessionId generate_session_id() {
  SessionId session_id;
  if (RAND_bytes(session_id.data(), session_id.size()) != 1) {
    throw std::runtime_error("Failed to generate session ID: " + get_openssl_error());
  }
  return session_id;
}

Key generate_key() {
  Key key;
  if (RAND_bytes(key.data(), key.size()) != 1) {
    throw std::runtime_error("Failed to generate random key: " + get_openssl_error());
  }
  return key;
}

IV generate_iv() {
  IV iv;
  if (RAND_bytes(iv.data(), iv.size()) != 1) {
    throw std::runtime_error("Failed to generate random IV: " + get_openssl_error());
  }
  return iv;
}

Key derive_session_key(const Key& pre_shared_key, const Nonce& client_nonce,
                       const Nonce& server_nonce) {
  Key session_key;

  // Prepare HKDF inputs
  // Salt is the XOR of client and server nonces
  std::vector<uint8_t> salt(NONCE_SIZE);
  for (size_t i = 0; i < NONCE_SIZE; ++i) {
    salt[i] = client_nonce[i] ^ server_nonce[i];
  }

  // Info is the concatenation of client and server nonces
  std::vector<uint8_t> info;
  info.reserve(client_nonce.size() + server_nonce.size());
  info.insert(info.end(), client_nonce.begin(), client_nonce.end());
  info.insert(info.end(), server_nonce.begin(), server_nonce.end());

  // Use OpenSSL's HKDF to derive the session key
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) {
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed: " + get_openssl_error());
  }

  if (EVP_PKEY_derive_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_derive_init failed: " + get_openssl_error());
  }

  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_CTX_set_hkdf_md failed: " + get_openssl_error());
  }

  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), salt.size()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_salt failed: " + get_openssl_error());
  }

  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, pre_shared_key.data(), pre_shared_key.size()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_CTX_set1_hkdf_key failed: " + get_openssl_error());
  }

  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), info.size()) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_CTX_add1_hkdf_info failed: " + get_openssl_error());
  }

  size_t keylen = session_key.size();
  if (EVP_PKEY_derive(pctx, session_key.data(), &keylen) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_derive failed: " + get_openssl_error());
  }

  EVP_PKEY_CTX_free(pctx);
  return session_key;
}

std::vector<uint8_t> compute_hmac(const Key& key, const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hmac_result(EVP_MAX_MD_SIZE);
  size_t hmac_len = 0;

  // Create a new EVP_MAC context for HMAC
  EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!mac) {
    throw std::runtime_error("EVP_MAC_fetch failed: " + get_openssl_error());
  }

  // Create a new MAC context
  EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
  if (!ctx) {
    EVP_MAC_free(mac);
    throw std::runtime_error("EVP_MAC_CTX_new failed: " + get_openssl_error());
  }

  // Create parameter list for initialization
  OSSL_PARAM params[2];
  const char* digest_name = "SHA256";
  params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest_name), 0);
  params[1] = OSSL_PARAM_construct_end();

  // Initialize the MAC context with the key and parameters
  if (!EVP_MAC_init(ctx, key.data(), key.size(), params)) {
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    throw std::runtime_error("EVP_MAC_init failed: " + get_openssl_error());
  }

  // Update the MAC with the data
  if (!EVP_MAC_update(ctx, data.data(), data.size())) {
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    throw std::runtime_error("EVP_MAC_update failed: " + get_openssl_error());
  }

  // Finalize and get the MAC value
  if (!EVP_MAC_final(ctx, hmac_result.data(), &hmac_len, hmac_result.size())) {
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    throw std::runtime_error("EVP_MAC_final failed: " + get_openssl_error());
  }

  // Clean up
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);

  // Resize the result to the actual MAC length
  hmac_result.resize(hmac_len);
  return hmac_result;
}

bool verify_hmac(const Key& key, const std::vector<uint8_t>& data,
                 const std::vector<uint8_t>& expected_hmac) {
  std::vector<uint8_t> computed_hmac = compute_hmac(key, data);

  if (computed_hmac.size() != expected_hmac.size()) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  return CRYPTO_memcmp(computed_hmac.data(), expected_hmac.data(), computed_hmac.size()) == 0;
}

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const Key& key, const IV& iv,
                             AuthTag& auth_tag) {
  // Prepare output buffer
  std::vector<uint8_t> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
  int len = 0, ciphertext_len = 0;

  // Create and initialize context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed: " + get_openssl_error());
  }

  // Initialize encryption operation
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex (1) failed: " + get_openssl_error());
  }

  // Set IV length (default is 12 bytes for GCM)
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IV length) failed: " + get_openssl_error());
  }

  // Initialize key and IV
  if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex (2) failed: " + get_openssl_error());
  }

  // Encrypt plaintext
  if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptUpdate failed: " + get_openssl_error());
  }
  ciphertext_len = len;

  // Finalize encryption
  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptFinal_ex failed: " + get_openssl_error());
  }
  ciphertext_len += len;

  // Get the authentication tag
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, auth_tag.size(), auth_tag.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl (get tag) failed: " + get_openssl_error());
  }

  EVP_CIPHER_CTX_free(ctx);

  // Resize ciphertext to actual length
  ciphertext.resize(ciphertext_len);
  return ciphertext;
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const Key& key, const IV& iv,
                             const AuthTag& auth_tag) {
  // Prepare output buffer
  std::vector<uint8_t> plaintext(ciphertext.size());
  int len = 0, plaintext_len = 0;

  // Create and initialize context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    throw std::runtime_error("EVP_CIPHER_CTX_new failed: " + get_openssl_error());
  }

  // Initialize decryption operation
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex (1) failed: " + get_openssl_error());
  }

  // Set IV length
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl (IV length) failed: " + get_openssl_error());
  }

  // Initialize key and IV
  if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex (2) failed: " + get_openssl_error());
  }

  // Decrypt ciphertext
  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed: " + get_openssl_error());
  }
  plaintext_len = len;

  // Set expected tag value
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, auth_tag.size(),
                          const_cast<void*>(static_cast<const void*>(auth_tag.data()))) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_CIPHER_CTX_ctrl (set tag) failed: " + get_openssl_error());
  }

  // Finalize decryption
  int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
  EVP_CIPHER_CTX_free(ctx);

  if (ret <= 0) {
    throw std::runtime_error("Authentication failed or decryption error: " + get_openssl_error());
  }

  plaintext_len += len;
  plaintext.resize(plaintext_len);
  return plaintext;
}

uint32_t calculate_crc32(const std::vector<uint8_t>& data) {
  // Generate CRC32 table on first use
  static const auto crc_table = []() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; i++) {
      uint32_t crc = i;
      for (size_t j = 0; j < 8; j++) {
        crc = (crc & 1) ? (0xEDB88320 ^ (crc >> 1)) : (crc >> 1);
      }
      table[i] = crc;
    }
    return table;
  }();

  uint32_t crc = 0xFFFFFFFF;
  for (auto byte : data) {
    crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
  }
  return crc ^ 0xFFFFFFFF;
}

Key get_preshared_key() {
  // First try to read from environment variable
  const char* key_env = std::getenv("STX_KEY");
  if (key_env) {
    std::string key_hex = key_env;
    if (key_hex.length() == KEY_SIZE * 2) {  // Hex string should be twice the key size
      Key key;
      for (size_t i = 0; i < KEY_SIZE; ++i) {
        std::string byte_str = key_hex.substr(i * 2, 2);
        key[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
      }
      return key;
    }
  }

  // If environment variable is not set or invalid, try to read from file
  const char* key_file_path = std::getenv("STX_KEY_FILE");
  if (key_file_path) {
    std::ifstream key_file(key_file_path, std::ios::binary);
    if (key_file) {
      Key key;
      key_file.read(reinterpret_cast<char*>(key.data()), key.size());
      if (key_file.gcount() == static_cast<std::streamsize>(key.size())) {
        return key;
      }
    }
  }

  // If neither environment variable nor file is available, generate a random key
  // This is mainly for testing purposes; in production, keys should be pre-shared
  std::cerr << "Warning: No pre-shared key found. Generating a random key for testing."
            << std::endl;
  Key key = generate_key();

  // Print the key in hex format for debugging
  std::cerr << "Generated key: ";
  for (auto byte : key) {
    std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::cerr << std::dec << std::endl;

  return key;
}

// Cache of client keys to avoid reading from disk repeatedly
static std::unordered_map<std::string, Key> client_key_cache;

// Location of client keys
static std::string client_keys_dir = "./client_keys";

// Get a client's key by ID
Key get_client_key(const std::string& client_id) {
  // Check if key is already in cache
  auto it = client_key_cache.find(client_id);
  if (it != client_key_cache.end()) {
    return it->second;
  }

  // Check environment variables first
  std::string env_var_name = "STX_KEY_" + client_id;
  const char* key_env = std::getenv(env_var_name.c_str());
  if (key_env) {
    std::string key_hex = key_env;
    if (key_hex.length() == KEY_SIZE * 2) {  // Hex string should be twice the key size
      Key key;
      for (size_t i = 0; i < KEY_SIZE; ++i) {
        std::string byte_str = key_hex.substr(i * 2, 2);
        key[i] = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
      }

      // Cache the key
      client_key_cache[client_id] = key;
      return key;
    }
  }

  // Try to read from client key file
  std::filesystem::path key_file_path =
      std::filesystem::path(client_keys_dir) / (client_id + ".key");
  if (std::filesystem::exists(key_file_path)) {
    std::ifstream key_file(key_file_path, std::ios::binary);
    if (key_file) {
      Key key;
      key_file.read(reinterpret_cast<char*>(key.data()), key.size());
      if (key_file.gcount() == static_cast<std::streamsize>(key.size())) {
        // Cache the key
        client_key_cache[client_id] = key;
        return key;
      }
    }
  }

  // If neither environment variable nor file is available, generate a random key
  // This is mainly for testing purposes; in production, keys should be pre-shared
  std::cerr << "Warning: No key found for client " << client_id
            << ". Generating a random key for testing." << std::endl;

  Key key = generate_key();

  // Print the key in hex format for debugging
  std::cerr << "Generated key for " << client_id << ": ";
  for (auto byte : key) {
    std::cerr << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
  }
  std::cerr << std::dec << std::endl;

  // Cache the key
  client_key_cache[client_id] = key;

  // Also save it to disk for future use
  try {
    std::filesystem::create_directories(client_keys_dir);
    std::ofstream key_file(key_file_path, std::ios::binary);
    if (key_file) {
      key_file.write(reinterpret_cast<const char*>(key.data()), key.size());
    }
  } catch (const std::exception& e) {
    std::cerr << "Error saving key file: " << e.what() << std::endl;
  }

  return key;
}

// Set the directory where client keys are stored
void set_client_keys_directory(const std::string& dir) {
  client_keys_dir = dir;
}

}  // namespace crypto
}  // namespace stx