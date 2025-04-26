// tests/test_crypto.cpp
#include "stx/crypto.h"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>


// Helper function to print test results
void print_result(const std::string& test_name, bool success) {
  std::cout << test_name << ": " << (success ? "PASS" : "FAIL") << std::endl;
}

// Test functions
bool test_initialization() {
  return stx::crypto::initialize();
}

bool test_nonce_generation() {
  auto nonce1 = stx::crypto::generate_nonce();
  auto nonce2 = stx::crypto::generate_nonce();

  // Two consecutive nonces should be different
  return nonce1 != nonce2;
}

bool test_key_generation() {
  auto key1 = stx::crypto::generate_key();
  auto key2 = stx::crypto::generate_key();

  // Two consecutive keys should be different
  return key1 != key2;
}

bool test_hmac() {
  stx::crypto::Key key = stx::crypto::generate_key();
  std::string message = "This is a test message for HMAC verification";
  std::vector<uint8_t> data(message.begin(), message.end());

  // Compute HMAC
  std::vector<uint8_t> hmac = stx::crypto::compute_hmac(key, data);

  // Verify the HMAC
  bool valid = stx::crypto::verify_hmac(key, data, hmac);

  // Modify the message and verify again (should fail)
  data[0] ^= 0xFF;
  bool invalid = !stx::crypto::verify_hmac(key, data, hmac);

  return valid && invalid;
}

bool test_encryption_decryption() {
  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::IV iv = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag;

  std::string plaintext = "This is a secret message that should be encrypted and decrypted";
  std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

  // Encrypt the data
  std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, key, iv, auth_tag);

  // Decrypt the data
  std::vector<uint8_t> decrypted = stx::crypto::decrypt(ciphertext, key, iv, auth_tag);

  // Check if the decrypted data matches the original
  bool matches = (data == decrypted);

  // Try to decrypt with a modified auth tag (should fail)
  stx::crypto::AuthTag modified_tag = auth_tag;
  modified_tag[0] ^= 0xFF;

  bool decryption_fails = false;
  try {
    stx::crypto::decrypt(ciphertext, key, iv, modified_tag);
  } catch (const std::exception&) {
    decryption_fails = true;
  }

  return matches && decryption_fails;
}

bool test_session_key_derivation() {
  stx::crypto::Key preshared_key = stx::crypto::generate_key();
  stx::crypto::Nonce client_nonce = stx::crypto::generate_nonce();
  stx::crypto::Nonce server_nonce = stx::crypto::generate_nonce();

  // Derive session key
  stx::crypto::Key session_key1 =
      stx::crypto::derive_session_key(preshared_key, client_nonce, server_nonce);

  // Derive again with the same inputs (should be the same)
  stx::crypto::Key session_key2 =
      stx::crypto::derive_session_key(preshared_key, client_nonce, server_nonce);

  // Derive with different nonces (should be different)
  stx::crypto::Nonce different_nonce = stx::crypto::generate_nonce();
  stx::crypto::Key session_key3 =
      stx::crypto::derive_session_key(preshared_key, different_nonce, server_nonce);

  return (session_key1 == session_key2) && (session_key1 != session_key3);
}

bool test_crc32() {
  std::string data1 = "Test data for CRC32 checksum";
  std::vector<uint8_t> bytes1(data1.begin(), data1.end());

  std::string data2 = "Test data for CRC32 checksum.";
  std::vector<uint8_t> bytes2(data2.begin(), data2.end());

  uint32_t checksum1 = stx::crypto::calculate_crc32(bytes1);
  uint32_t checksum1_again = stx::crypto::calculate_crc32(bytes1);
  uint32_t checksum2 = stx::crypto::calculate_crc32(bytes2);

  // The same data should produce the same checksum
  bool same_checksums = (checksum1 == checksum1_again);

  // Different data should produce different checksums
  bool different_checksums = (checksum1 != checksum2);

  return same_checksums && different_checksums;
}

int main() {
  // Run all tests
  bool init_test = test_initialization();
  print_result("Initialization", init_test);

  if (!init_test) {
    std::cerr << "Initialization failed, cannot proceed with other tests" << std::endl;
    return 1;
  }

  print_result("Nonce Generation", test_nonce_generation());
  print_result("Key Generation", test_key_generation());
  print_result("HMAC", test_hmac());
  print_result("Encryption/Decryption", test_encryption_decryption());
  print_result("Session Key Derivation", test_session_key_derivation());
  print_result("CRC32 Checksum", test_crc32());

  // Clean up
  stx::crypto::cleanup();

  return 0;
}