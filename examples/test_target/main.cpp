#include "http_operations.hpp"
#include "crypto_operations.hpp"
#include "network_operations.hpp"
#include "gui_login.hpp"

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

void print_banner() {
    std::cout << "========================================\n";
    std::cout << "  ExLoader Test Target Application\n";
    std::cout << "========================================\n";
    std::cout << "This application exercises all hook points:\n";
    std::cout << "  - WinHTTP, WinInet, Winsock\n";
    std::cout << "  - URLMon, Proxy APIs\n";
    std::cout << "  - BCrypt, CryptoAPI\n";
    std::cout << "========================================\n\n";
}

void test_scenario_user_authentication() {
    std::cout << "[Scenario 1] User Authentication Flow\n";
    std::cout << "--------------------------------------\n";

    // 1. Fetch user data from API
    std::cout << "1. Fetching user data via WinHTTP...\n";
    auto response = test_target::winhttp_get("https://httpbin.org/json");
    if (response.success) {
        std::cout << "   Status: " << response.status_code << "\n";
        std::cout << "   Data size: " << response.body.size() << " bytes\n";
    }

    // 2. Encrypt the user data with BCrypt
    std::cout << "2. Encrypting user data with BCrypt (AES-256)...\n";
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    std::vector<uint8_t> plaintext(response.body.begin(), response.body.end());
    auto encrypted = test_target::bcrypt_aes_encrypt(plaintext, key);
    std::cout << "   Encrypted size: " << encrypted.size() << " bytes\n";

    // 3. Decrypt to verify
    std::cout << "3. Decrypting with BCrypt...\n";
    auto decrypted = test_target::bcrypt_aes_decrypt(encrypted, key);
    std::cout << "   Decrypted size: " << decrypted.size() << " bytes\n";
    std::cout << "   Match: " << (decrypted == plaintext ? "YES" : "NO") << "\n\n";
}

void test_scenario_data_submission() {
    std::cout << "[Scenario 2] Encrypted Data Submission\n";
    std::cout << "---------------------------------------\n";

    // 1. Prepare user data
    std::string userData = R"({"username":"testuser","password":"secret123","email":"test@example.com"})";
    std::cout << "1. Preparing user data: " << userData.size() << " bytes\n";

    // 2. Encrypt with CryptoAPI
    std::cout << "2. Encrypting with CryptoAPI (AES-256)...\n";
    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5,
        0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe
    };

    std::vector<uint8_t> plainData(userData.begin(), userData.end());
    auto encryptedData = test_target::cryptoapi_aes_encrypt(plainData, key);
    std::cout << "   Encrypted size: " << encryptedData.size() << " bytes\n";

    // 3. Send encrypted data via WinInet POST
    std::cout << "3. Sending encrypted data via WinInet POST...\n";
    std::string base64Data; // In real scenario, we'd base64 encode
    for (auto byte : encryptedData) {
        char hex[3];
        sprintf(hex, "%02x", byte);
        base64Data += hex;
    }

    std::string postData = R"({"encrypted_data":")" + base64Data.substr(0, 100) + R"(..."})";
    auto response = test_target::wininet_post("https://httpbin.org/post", postData);
    if (response.success) {
        std::cout << "   Response size: " << response.body.size() << " bytes\n";
    }
    std::cout << "\n";
}

void test_scenario_file_download() {
    std::cout << "[Scenario 3] Secure File Download\n";
    std::cout << "----------------------------------\n";

    // 1. Download file with URLMon
    std::cout << "1. Downloading via URLMon...\n";
    bool success = test_target::urlmon_download("https://httpbin.org/robots.txt", "downloaded.txt");
    std::cout << "   Download: " << (success ? "SUCCESS" : "FAILED") << "\n";

    // 2. Hash the downloaded file
    if (success) {
        std::cout << "2. Computing SHA-256 hash with BCrypt...\n";
        std::string hash = test_target::bcrypt_sha256("User-agent: *\nDisallow: /deny\n");
        std::cout << "   Hash: " << hash << "\n";
    }
    std::cout << "\n";
}

void test_scenario_multiple_apis() {
    std::cout << "[Scenario 4] Multiple API Usage\n";
    std::cout << "--------------------------------\n";

    std::cout << "1. Testing WinHTTP GET...\n";
    auto r1 = test_target::winhttp_get("https://httpbin.org/user-agent");
    std::cout << "   Status: " << r1.status_code << "\n";

    std::cout << "2. Testing WinInet GET...\n";
    auto r2 = test_target::wininet_get("https://httpbin.org/headers");
    std::cout << "   Size: " << r2.body.size() << " bytes\n";

    std::cout << "3. Testing Winsock connection...\n";
    bool connected = test_target::winsock_connect_test("httpbin.org", 80);
    std::cout << "   Connected: " << (connected ? "YES" : "NO") << "\n";

    std::cout << "4. Testing proxy settings...\n";
    test_target::test_proxy_settings();
    std::cout << "   Proxy check completed\n\n";
}

void test_scenario_crypto_operations() {
    std::cout << "[Scenario 5] Pure Crypto Operations\n";
    std::cout << "------------------------------------\n";

    std::string sensitiveData = "Credit Card: 1234-5678-9012-3456, CVV: 123, Expiry: 12/25";
    std::vector<uint8_t> data(sensitiveData.begin(), sensitiveData.end());

    std::vector<uint8_t> key1 = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    std::cout << "1. Encrypting sensitive data with BCrypt...\n";
    auto enc1 = test_target::bcrypt_aes_encrypt(data, key1);
    std::cout << "   Encrypted: " << enc1.size() << " bytes\n";

    auto dec1 = test_target::bcrypt_aes_decrypt(enc1, key1);
    std::cout << "   Decrypted: " << (dec1 == data ? "MATCH" : "MISMATCH") << "\n";

    std::cout << "2. Encrypting with CryptoAPI...\n";
    auto enc2 = test_target::cryptoapi_aes_encrypt(data, key1);
    std::cout << "   Encrypted: " << enc2.size() << " bytes\n";

    auto dec2 = test_target::cryptoapi_aes_decrypt(enc2, key1);
    std::cout << "   Decrypted: " << (dec2 == data ? "MATCH" : "MISMATCH") << "\n";

    std::cout << "3. Computing hash...\n";
    std::string hash = test_target::bcrypt_sha256(sensitiveData);
    std::cout << "   SHA-256: " << hash << "\n\n";
}

void test_scenario_gui_login() {
    std::cout << "[Scenario 6] GUI Login + Serial Validation\n";
    std::cout << "-------------------------------------------\n";
    std::cout << "Launching demo window...\n";
    test_target::run_gui_login_demo();
    std::cout << "Window closed.\n\n";
}

void run_all_scenarios() {
    print_banner();

    test_scenario_gui_login();

    std::cout << "========================================\n";
    std::cout << "GUI scenario completed.\n";
    std::cout << "========================================\n";
}

int main(int argc, char** argv) {
    std::cout << "Starting test scenarios...\n\n";

    try {
        run_all_scenarios();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
