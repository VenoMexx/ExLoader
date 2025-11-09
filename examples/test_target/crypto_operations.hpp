#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace test_target {

// BCrypt/CNG operations
std::vector<uint8_t> bcrypt_aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key);
std::vector<uint8_t> bcrypt_aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key);

// CryptoAPI operations
std::vector<uint8_t> cryptoapi_aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key);
std::vector<uint8_t> cryptoapi_aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key);

// Hash operations
std::string bcrypt_sha256(const std::string& data);
std::string bcrypt_md5(const std::string& data);

}  // namespace test_target
