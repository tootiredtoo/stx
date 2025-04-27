#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <random>
#include <string>
#include <thread>
#include <vector>
#include "crypto/crypto.hpp"

class CryptoTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(stx::crypto::initialize()); }

  static void TearDownTestSuite() { stx::crypto::cleanup(); }

  std::vector<uint8_t> generateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (size_t i = 0; i < size; ++i) {
      data[i] = dist(gen);
    }

    return data;
  }
};

// Test nonce generation randomness
TEST_F(CryptoTest, NonceGenerationProducesUniqueValues) {
  const size_t nonce_count = 1000;
  std::set<stx::crypto::Nonce> nonces;

  for (size_t i = 0; i < nonce_count; ++i) {
    auto nonce = stx::crypto::generate_nonce();
    nonces.insert(nonce);
  }

  // Check that all generated nonces are unique
  EXPECT_EQ(nonces.size(), nonce_count) << "Found duplicate nonces";
}

// Test session ID generation randomness
TEST_F(CryptoTest, SessionIdGenerationProducesUniqueValues) {
  const size_t id_count = 1000;
  std::set<stx::crypto::SessionId> session_ids;

  for (size_t i = 0; i < id_count; ++i) {
    session_ids.insert(stx::crypto::generate_session_id());
  }

  // Check that all generated session IDs are unique
  EXPECT_EQ(session_ids.size(), id_count) << "Found duplicate session IDs";
}

// Test HMAC with empty data
TEST_F(CryptoTest, HMACWithEmptyData) {
  stx::crypto::Key key = stx::crypto::generate_key();
  std::vector<uint8_t> empty_data;
  std::vector<uint8_t> hmac = stx::crypto::compute_hmac(key, empty_data);

  EXPECT_FALSE(hmac.empty());
  EXPECT_TRUE(stx::crypto::verify_hmac(key, empty_data, hmac));
}

// Test HMAC with large data
TEST_F(CryptoTest, HMACWithLargeData) {
  stx::crypto::Key key = stx::crypto::generate_key();
  // Create a 10MB data block
  std::vector<uint8_t> large_data = generateRandomData(10 * 1024 * 1024);
  std::vector<uint8_t> hmac = stx::crypto::compute_hmac(key, large_data);

  EXPECT_TRUE(stx::crypto::verify_hmac(key, large_data, hmac));

  size_t middle_index = large_data.size() / 2;
  large_data[middle_index] ^= 0xFF;

  EXPECT_FALSE(stx::crypto::verify_hmac(key, large_data, hmac));
}

// Test encryption with different data sizes
TEST_F(CryptoTest, EncryptionWithVariousDataSizes) {
  std::vector<size_t> test_sizes = {
      0,                // Empty
      1,                // Single byte
      15,               // Less than a block
      16,               // Exactly one block
      17,               // Just over one block
      1023,             // Just under 1KB
      1024,             // Exactly 1KB
      1025,             // Just over 1KB
      1024 * 1024 - 1,  // Just under 1MB
      1024 * 1024,      // Exactly 1MB
      1024 * 1024 + 1   // Just over 1MB
  };

  for (size_t size : test_sizes) {
    SCOPED_TRACE("Testing with data size: " + std::to_string(size));

    stx::crypto::Key key = stx::crypto::generate_key();
    stx::crypto::IV iv = stx::crypto::generate_iv();
    stx::crypto::AuthTag auth_tag;

    std::vector<uint8_t> data = generateRandomData(size);
    std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, key, iv, auth_tag);

    // Verify the ciphertext size (should be at least the plaintext size)
    if (size > 0) {
      EXPECT_GE(ciphertext.size(), data.size());
    }

    std::vector<uint8_t> decrypted = stx::crypto::decrypt(ciphertext, key, iv, auth_tag);

    EXPECT_EQ(data, decrypted);
  }
}

// Test encryption with all-zero data
TEST_F(CryptoTest, EncryptionWithZeroData) {
  std::vector<uint8_t> zero_data(1024, 0);

  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::IV iv = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag;
  std::vector<uint8_t> ciphertext = stx::crypto::encrypt(zero_data, key, iv, auth_tag);

  // Ciphertext should not be all zeros
  bool all_zeros =
      std::all_of(ciphertext.begin(), ciphertext.end(), [](uint8_t b) { return b == 0; });
  EXPECT_FALSE(all_zeros) << "Ciphertext should not be all zeros";

  std::vector<uint8_t> decrypted = stx::crypto::decrypt(ciphertext, key, iv, auth_tag);
  EXPECT_EQ(zero_data, decrypted);
}

// Test encryption with same plaintext but different IVs
TEST_F(CryptoTest, EncryptionWithSamePlaintextDifferentIVs) {
  // Same plaintext, different IVs should produce different ciphertexts
  std::string plaintext = "This is a test message that will be encrypted multiple times";
  std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::IV iv1 = stx::crypto::generate_iv();
  stx::crypto::IV iv2 = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag1;
  stx::crypto::AuthTag auth_tag2;

  std::vector<uint8_t> ciphertext1 = stx::crypto::encrypt(data, key, iv1, auth_tag1);
  std::vector<uint8_t> ciphertext2 = stx::crypto::encrypt(data, key, iv2, auth_tag2);

  EXPECT_NE(ciphertext1, ciphertext2);

  EXPECT_NE(auth_tag1, auth_tag2);

  std::vector<uint8_t> decrypted1 = stx::crypto::decrypt(ciphertext1, key, iv1, auth_tag1);
  std::vector<uint8_t> decrypted2 = stx::crypto::decrypt(ciphertext2, key, iv2, auth_tag2);

  EXPECT_EQ(data, decrypted1);
  EXPECT_EQ(data, decrypted2);
}

// Test decryption with wrong key
TEST_F(CryptoTest, DecryptionWithWrongKey) {
  std::string plaintext = "This is a test message for encryption";
  std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

  stx::crypto::Key correct_key = stx::crypto::generate_key();
  stx::crypto::Key wrong_key = stx::crypto::generate_key();
  stx::crypto::IV iv = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag;

  std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, correct_key, iv, auth_tag);

  // Decryption with wrong key should fail
  EXPECT_THROW(stx::crypto::decrypt(ciphertext, wrong_key, iv, auth_tag), std::runtime_error);
}

// Test decryption with wrong IV
TEST_F(CryptoTest, DecryptionWithWrongIV) {
  std::string plaintext = "This is a test message for encryption";
  std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::IV correct_iv = stx::crypto::generate_iv();
  stx::crypto::IV wrong_iv = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag;

  std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, key, correct_iv, auth_tag);

  // Decryption with wrong IV should fail
  EXPECT_THROW(stx::crypto::decrypt(ciphertext, key, wrong_iv, auth_tag), std::runtime_error);
}

// Test tampering with ciphertext
TEST_F(CryptoTest, CiphertextTampering) {
  std::string plaintext = "This is a test message for encryption";
  std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::IV iv = stx::crypto::generate_iv();
  stx::crypto::AuthTag auth_tag;

  std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, key, iv, auth_tag);

  // Change random byte
  if (!ciphertext.empty()) {
    size_t index = rand() % ciphertext.size();
    ciphertext[index] ^= 0xFF;

    // Decryption should fail
    EXPECT_THROW(stx::crypto::decrypt(ciphertext, key, iv, auth_tag), std::runtime_error);
  }
}

// Test session key derivation with edge cases
TEST_F(CryptoTest, SessionKeyDerivationEdgeCases) {
  stx::crypto::Key zero_key;
  stx::crypto::Nonce zero_nonce;

  std::fill(zero_key.begin(), zero_key.end(), 0);
  std::fill(zero_nonce.begin(), zero_nonce.end(), 0);

  // Derive session key with all-zero inputs (should still give non-zero output)
  stx::crypto::Key session_key = stx::crypto::derive_session_key(zero_key, zero_nonce, zero_nonce);

  // Check that the derived key is not all zeros
  bool all_zeros =
      std::all_of(session_key.begin(), session_key.end(), [](uint8_t b) { return b == 0; });
  EXPECT_FALSE(all_zeros) << "Session key should not be all zeros even with zero inputs";

  // Test input sensitivity - small changes should result in different keys
  stx::crypto::Key key = stx::crypto::generate_key();
  stx::crypto::Nonce nonce1 = stx::crypto::generate_nonce();
  stx::crypto::Nonce nonce2 = nonce1;

  nonce2[0] ^= 0x01;
  stx::crypto::Key key1 = stx::crypto::derive_session_key(key, nonce1, nonce2);

  nonce2[0] ^= 0x02;
  stx::crypto::Key key2 = stx::crypto::derive_session_key(key, nonce1, nonce2);

  EXPECT_NE(key1, key2);
}

// Test CRC32 with known test vectors
TEST_F(CryptoTest, CRC32KnownTestVectors) {
  struct TestVector {
    std::string input;
    uint32_t expected_crc;
  };

  std::vector<TestVector> test_vectors = {
      {"", 0x00000000},
      {"a", 0xE8B7BE43},
      {"abc", 0x352441C2},
      {"message digest", 0x20159D7F},
      {"abcdefghijklmnopqrstuvwxyz", 0x4C2750BD},
      {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 0x1FC2E6D2},
      {"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
       0x7CA94A72}};

  for (const auto& test_vector : test_vectors) {
    SCOPED_TRACE("Testing CRC32 with input: " + test_vector.input);

    std::vector<uint8_t> data(test_vector.input.begin(), test_vector.input.end());
    uint32_t crc = stx::crypto::calculate_crc32(data);

    EXPECT_EQ(crc, test_vector.expected_crc);
  }
}

// Test for CRC32 robustness
TEST_F(CryptoTest, CRC32Robustness) {
  std::string base_message = "This is a test message for CRC32 calculation";
  std::vector<uint8_t> base_data(base_message.begin(), base_message.end());

  uint32_t base_crc = stx::crypto::calculate_crc32(base_data);

  for (size_t i = 0; i < base_data.size(); ++i) {
    SCOPED_TRACE("Testing CRC32 change at position " + std::to_string(i));

    std::vector<uint8_t> modified_data = base_data;
    modified_data[i] ^= 0xFF;  // Flip all bits in the byte

    uint32_t modified_crc = stx::crypto::calculate_crc32(modified_data);

    // A change in any byte should result in a different CRC
    EXPECT_NE(base_crc, modified_crc) << "CRC32 failed to detect change at position " << i;
  }

  std::vector<size_t> test_sizes = {1, 10, 100, 1000, 10000};

  for (size_t size : test_sizes) {
    SCOPED_TRACE("Testing CRC32 with size " + std::to_string(size));

    std::vector<uint8_t> data1 = generateRandomData(size);
    std::vector<uint8_t> data2 = generateRandomData(size);

    if (data1 == data2 && !data1.empty()) {
      data2[0] ^= 0xFF;
    }

    uint32_t crc1 = stx::crypto::calculate_crc32(data1);
    uint32_t crc2 = stx::crypto::calculate_crc32(data2);

    // Different data should have different CRCs (with high probability)
    // There is a tiny chance of collision, but it's extremely unlikely
    EXPECT_NE(crc1, crc2) << "CRC32 produced same value for different data of size " << size;
  }
}

// Test thread safety of crypto operations
TEST_F(CryptoTest, ThreadSafety) {
  const int num_threads = 10;
  const int iterations_per_thread = 100;

  std::vector<std::thread> threads;
  std::atomic<bool> failure(false);

  for (int i = 0; i < num_threads; ++i) {
    threads.emplace_back([iterations_per_thread, &failure]() {
      try {
        for (int j = 0; j < iterations_per_thread; ++j) {
          stx::crypto::Nonce client_nonce = stx::crypto::generate_nonce();
          stx::crypto::Nonce server_nonce = stx::crypto::generate_nonce();

          stx::crypto::Key preshared_key = stx::crypto::generate_key();
          stx::crypto::Key session_key =
              stx::crypto::derive_session_key(preshared_key, client_nonce, server_nonce);

          stx::crypto::IV iv = stx::crypto::generate_iv();

          std::string test_data = "Thread test data " + std::to_string(j);
          std::vector<uint8_t> data(test_data.begin(), test_data.end());

          std::vector<uint8_t> hmac = stx::crypto::compute_hmac(session_key, data);

          if (!stx::crypto::verify_hmac(session_key, data, hmac)) {
            failure = true;
          }

          stx::crypto::AuthTag auth_tag;
          std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, session_key, iv, auth_tag);
          std::vector<uint8_t> decrypted =
              stx::crypto::decrypt(ciphertext, session_key, iv, auth_tag);

          if (data != decrypted) {
            failure = true;
          }
        }
      } catch (const std::exception& e) {
        std::cerr << "Thread exception: " << e.what() << std::endl;
        failure = true;
      }
    });
  }

  // Wait for all threads to complete
  for (auto& thread : threads) {
    thread.join();
  }

  EXPECT_FALSE(failure) << "Thread safety test failed";
}

// Test get_preshared_key functionality
TEST_F(CryptoTest, GetPresharedKey) {
  // Save original environment variables
  auto get_env_var = [](const char* name) -> std::string {
    const char* value = getenv(name);
    return value ? std::string(value) : "";
  };

  const std::string orig_env = get_env_var("STX_KEY");
  const std::string orig_file_env = get_env_var("STX_KEY_FILE");

  // Build a test key hex string
  std::string test_key_hex;
  for (size_t i = 0; i < stx::crypto::KEY_SIZE; ++i) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned int>(i & 0xFF));
    test_key_hex += hex;
  }

  // Set environment variables for the test
#ifdef _WIN32
  _putenv_s("STX_KEY", test_key_hex.c_str());
  _putenv_s("STX_KEY_FILE", "");  // Clear file env var
#else
  setenv("STX_KEY", test_key_hex.c_str(), 1);
  unsetenv("STX_KEY_FILE");  // Clear file env var
#endif

  stx::crypto::Key key = stx::crypto::get_preshared_key();

  // Verify key content (first few bytes)
  for (int i = 0; i < 5; ++i) {
    EXPECT_EQ(key[i], static_cast<uint8_t>(i & 0xFF));
  }

  // Restore original environment
#ifdef _WIN32
  _putenv_s("STX_KEY", orig_env.empty() ? "" : orig_env.c_str());
  _putenv_s("STX_KEY_FILE", orig_file_env.empty() ? "" : orig_file_env.c_str());
#else
  if (!orig_env.empty()) {
    setenv("STX_KEY", orig_env.c_str(), 1);
  } else {
    unsetenv("STX_KEY");
  }

  if (!orig_file_env.empty()) {
    setenv("STX_KEY_FILE", orig_file_env.c_str(), 1);
  } else {
    unsetenv("STX_KEY_FILE");
  }
#endif
}

// Stress test with large data and multiple operations
TEST_F(CryptoTest, StressTest) {
  const size_t data_size = 10 * 1024 * 1024;  // 10 MB
  const int iterations = 5;

  for (int i = 0; i < iterations; ++i) {
    SCOPED_TRACE("Stress test iteration " + std::to_string(i));

    std::vector<uint8_t> data = generateRandomData(data_size);

    stx::crypto::Key key = stx::crypto::generate_key();
    stx::crypto::IV iv = stx::crypto::generate_iv();
    stx::crypto::AuthTag auth_tag;

    // Measure encryption time
    auto start_encrypt = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> ciphertext = stx::crypto::encrypt(data, key, iv, auth_tag);
    auto end_encrypt = std::chrono::high_resolution_clock::now();

    // Measure decryption time
    auto start_decrypt = std::chrono::high_resolution_clock::now();
    std::vector<uint8_t> decrypted = stx::crypto::decrypt(ciphertext, key, iv, auth_tag);
    auto end_decrypt = std::chrono::high_resolution_clock::now();

    EXPECT_EQ(data, decrypted);

    auto encrypt_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_encrypt - start_encrypt).count();
    auto decrypt_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_decrypt - start_decrypt).count();

    std::cout << "Encryption of " << (data_size / (1024 * 1024)) << "MB took " << encrypt_ms
              << "ms (" << (data_size / (1024.0 * encrypt_ms)) << " MB/s)" << std::endl;

    std::cout << "Decryption of " << (data_size / (1024 * 1024)) << "MB took " << decrypt_ms
              << "ms (" << (data_size / (1024.0 * decrypt_ms)) << " MB/s)" << std::endl;
  }
}