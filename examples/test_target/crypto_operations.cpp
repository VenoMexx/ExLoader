#include "crypto_operations.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

namespace test_target {

std::vector<uint8_t> bcrypt_aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> ciphertext;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    // Open algorithm provider
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        return ciphertext;
    }

    // Set chaining mode to CBC
    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    // Generate key
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey,
                                                    nullptr, 0,
                                                    const_cast<PUCHAR>(key.data()), key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    // Calculate output size
    DWORD cbResult = 0;
    ULONG cbCiphertext = 0;
    if (!BCRYPT_SUCCESS(BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext.data()), plaintext.size(),
                                      nullptr, nullptr, 0, nullptr, 0, &cbCiphertext, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ciphertext;
    }

    // Allocate output buffer
    ciphertext.resize(cbCiphertext);

    // Encrypt
    UCHAR iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    if (BCRYPT_SUCCESS(BCryptEncrypt(hKey, const_cast<PUCHAR>(plaintext.data()), plaintext.size(),
                                     nullptr, iv, sizeof(iv),
                                     ciphertext.data(), cbCiphertext, &cbResult, BCRYPT_BLOCK_PADDING))) {
        ciphertext.resize(cbResult);
    } else {
        ciphertext.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return ciphertext;
}

std::vector<uint8_t> bcrypt_aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> plaintext;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0))) {
        return plaintext;
    }

    if (!BCRYPT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey,
                                                    nullptr, 0,
                                                    const_cast<PUCHAR>(key.data()), key.size(), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    ULONG cbPlaintext = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext.data()), ciphertext.size(),
                                      nullptr, nullptr, 0, nullptr, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING))) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return plaintext;
    }

    plaintext.resize(cbPlaintext);

    UCHAR iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    ULONG cbResult = 0;

    if (BCRYPT_SUCCESS(BCryptDecrypt(hKey, const_cast<PUCHAR>(ciphertext.data()), ciphertext.size(),
                                     nullptr, iv, sizeof(iv),
                                     plaintext.data(), cbPlaintext, &cbResult, BCRYPT_BLOCK_PADDING))) {
        plaintext.resize(cbResult);
    } else {
        plaintext.clear();
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return plaintext;
}

std::vector<uint8_t> cryptoapi_aes_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> ciphertext;

    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return ciphertext;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return ciphertext;
    }

    if (!CryptHashData(hHash, key.data(), key.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return ciphertext;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return ciphertext;
    }

    // Copy plaintext to modifiable buffer
    ciphertext = plaintext;
    DWORD dataLen = ciphertext.size();
    DWORD bufferLen = dataLen + 16; // Add padding space
    ciphertext.resize(bufferLen);

    if (CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &dataLen, bufferLen)) {
        ciphertext.resize(dataLen);
    } else {
        ciphertext.clear();
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ciphertext;
}

std::vector<uint8_t> cryptoapi_aes_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> plaintext;

    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return plaintext;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return plaintext;
    }

    if (!CryptHashData(hHash, key.data(), key.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return plaintext;
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return plaintext;
    }

    plaintext = ciphertext;
    DWORD dataLen = plaintext.size();

    if (CryptDecrypt(hKey, 0, TRUE, 0, plaintext.data(), &dataLen)) {
        plaintext.resize(dataLen);
    } else {
        plaintext.clear();
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return plaintext;
}

std::string bcrypt_sha256(const std::string& data) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
        return "";
    }

    DWORD hashLength = 0;
    DWORD resultLength = 0;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH,
                                          (PUCHAR)&hashLength, sizeof(hashLength), &resultLength, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data.data(), data.size(), 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    std::vector<uint8_t> hash(hashLength);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, hash.data(), hashLength, 0))) {
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    // Convert to hex string
    std::string result;
    for (uint8_t byte : hash) {
        char hex[3];
        sprintf(hex, "%02x", byte);
        result += hex;
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}

std::string bcrypt_md5(const std::string& data) {
    // Use CryptoAPI for MD5 (BCrypt doesn't have MD5 in MinGW headers)
    // Using ANSI version for better hook compatibility
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(data.data()), data.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashLen = 16;  // MD5 is always 16 bytes
    BYTE hashBytes[16];
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // Convert to hex string
    std::string result;
    for (DWORD i = 0; i < hashLen; i++) {
        char hex[3];
        sprintf(hex, "%02x", hashBytes[i]);
        result += hex;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return result;
}

}  // namespace test_target
