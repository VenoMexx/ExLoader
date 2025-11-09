#include "gui_login.hpp"
#include "modern_ui.hpp"
#include "http_operations.hpp"
#include "crypto_operations.hpp"
#include "network_operations.hpp"
#include "http_server.hpp"

#include <windows.h>
#include <commctrl.h>
#include <richedit.h>

#include <string>
#include <fstream>
#include <filesystem>
#include <vector>
#include <cstdio>
#include <cwctype>
#include <sstream>
#include <algorithm>
#include <map>
#include <mutex>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Msftedit.lib")

namespace test_target {

namespace {

// ============================================================================
// Constants
// ============================================================================

constexpr int kWindowWidth = 1280;
constexpr int kWindowHeight = 720;
constexpr int kTelemetryWidth = 420;
constexpr int kMainContentWidth = kWindowWidth - kTelemetryWidth - 50;

enum ControlId {
    ID_TAB = 400,
    ID_BTN_STAGE1 = 401,
    ID_BTN_STAGE2 = 402,
    ID_BTN_STAGE3 = 403,
    ID_TELEMETRY_LOG = 500,
    ID_TIMER_ANIMATE = 1000
};

// ============================================================================
// Stage System
// ============================================================================

enum class StageId {
    Authentication = 0,
    LicenseValidation = 1,
    TimeBomb = 2,
    COUNT
};

struct StageInfo {
    StageId id;
    std::wstring title;
    std::wstring description;
    bool unlocked;
    bool completed;
    COLORREF accent_color;
};

std::vector<StageInfo> g_stages = {
    {StageId::Authentication, L"Authentication", L"Authenticate with username and password", true, false, modern_ui::colors::accent_blue},
    {StageId::LicenseValidation, L"License Validation", L"Validate your serial key", false, false, modern_ui::colors::accent_purple},
    {StageId::TimeBomb, L"File Validation", L"Verify offline licence artefact", false, false, modern_ui::colors::accent_orange}
};

// ============================================================================
// HTTP Server & Crypto
// ============================================================================

std::unique_ptr<SimpleHttpServer> g_http_server;

// Shared AES-256 key for client-server communication
std::vector<uint8_t> get_shared_aes_key() {
    return {
        0xC0, 0xFF, 0xEE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE,
        0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xD0, 0x0D, 0xF0,
        0x0D, 0x13, 0x37, 0xC0, 0xDE, 0x42, 0x69, 0x88,
        0xFF, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    };
}

// Reversed key for server responses (asymmetric approach)
std::vector<uint8_t> get_reversed_aes_key() {
    auto key = get_shared_aes_key();
    std::reverse(key.begin(), key.end());
    return key;
}

// ============================================================================
// Telemetry System
// ============================================================================

struct TelemetryEntry {
    std::wstring timestamp;
    std::wstring hook_type;
    std::wstring message;
    COLORREF color;
};

std::vector<TelemetryEntry> g_telemetry;
std::mutex g_telemetry_mutex;
size_t g_last_telemetry_count = 0;

void add_telemetry(const std::wstring& hook_type, const std::wstring& message, COLORREF color = modern_ui::colors::text_secondary) {
    std::lock_guard<std::mutex> lock(g_telemetry_mutex);

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[32];
    swprintf(timestamp, 32, L"%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    g_telemetry.push_back({timestamp, hook_type, message, color});

    // Keep last 100 entries
    if (g_telemetry.size() > 100) {
        g_telemetry.erase(g_telemetry.begin());
    }
}

// ============================================================================
// UI State & Theme Colors
// ============================================================================

// Modern dark theme colors (aligned with modern_ui palette)
constexpr COLORREF kColorBackground = modern_ui::colors::background_dark;
constexpr COLORREF kColorPanel = modern_ui::colors::background_medium;
constexpr COLORREF kColorBorder = modern_ui::colors::border;
constexpr COLORREF kColorText = modern_ui::colors::text_primary;
constexpr COLORREF kColorTextDim = modern_ui::colors::text_muted;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
HWND g_tab = nullptr;
HWND g_panels[3]{};
HWND g_telemetry_box = nullptr;
HWND g_status_bar = nullptr;

HFONT g_font_title = nullptr;
HFONT g_font_normal = nullptr;
HFONT g_font_small = nullptr;
HFONT g_font_mono = nullptr;

HBRUSH g_brush_background = nullptr;
HBRUSH g_brush_panel = nullptr;

StageId g_current_stage = StageId::Authentication;
int g_achievement_count = 0;

// ============================================================================
// Helper Functions
// ============================================================================

std::wstring format_time(const SYSTEMTIME& st) {
    wchar_t buffer[64];
    swprintf(buffer, 64, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

std::wstring read_text(HWND edit) {
    const int len = GetWindowTextLengthW(edit);
    if (len == 0) return L"";
    std::wstring text(static_cast<size_t>(len), L'\0');
    GetWindowTextW(edit, text.data(), len + 1);
    return text;
}

std::string narrow_utf8(const std::wstring& text) {
    if (text.empty()) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                          static_cast<int>(text.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return {};
    std::string result(static_cast<size_t>(size_needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        result.data(), size_needed, nullptr, nullptr);
    return result;
}

std::wstring widen_utf8(const std::string& text) {
    if (text.empty()) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                          static_cast<int>(text.size()), nullptr, 0);
    if (size_needed <= 0) return {};
    std::wstring result(static_cast<size_t>(size_needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                        result.data(), size_needed);
    return result;
}

void unlock_stage(StageId stage_id) {
    size_t idx = static_cast<size_t>(stage_id);
    if (idx < g_stages.size()) {
        g_stages[idx].unlocked = true;
        add_telemetry(L"SYSTEM", L"Stage unlocked: " + g_stages[idx].title, modern_ui::colors::accent_green);
    }
}

void complete_stage(StageId stage_id) {
    size_t idx = static_cast<size_t>(stage_id);
    if (idx < g_stages.size()) {
        g_stages[idx].completed = true;
        add_telemetry(L"SYSTEM", L"Stage completed: " + g_stages[idx].title, modern_ui::colors::success);

        // Unlock next stage
        if (idx + 1 < g_stages.size()) {
            unlock_stage(static_cast<StageId>(idx + 1));
        }
    }
}

void update_telemetry_display() {
    if (!g_telemetry_box) return;

    std::lock_guard<std::mutex> lock(g_telemetry_mutex);

    // Only update if there are new entries
    if (g_telemetry.size() == g_last_telemetry_count) {
        return;  // No changes, skip update
    }

    g_last_telemetry_count = g_telemetry.size();

    // Build plain text content
    std::wstring plain;
    for (const auto& entry : g_telemetry) {
        plain += entry.timestamp + L" [" + entry.hook_type + L"] " + entry.message + L"\r\n";
    }

    // Save scroll position if user is NOT at the bottom
    SCROLLINFO si = {sizeof(SCROLLINFO), SIF_ALL};
    GetScrollInfo(g_telemetry_box, SB_VERT, &si);
    bool was_at_bottom = (si.nPos >= si.nMax - static_cast<int>(si.nPage));

    // Update text
    SetWindowTextW(g_telemetry_box, plain.c_str());

    // Only auto-scroll if user was at bottom (or first update)
    if (was_at_bottom || g_last_telemetry_count <= 1) {
        // Use EM_SETSEL to move caret to end, then scroll to caret
        int len = GetWindowTextLengthW(g_telemetry_box);
        SendMessageW(g_telemetry_box, EM_SETSEL, len, len);
        SendMessageW(g_telemetry_box, EM_SCROLLCARET, 0, 0);
    }
}

// ============================================================================
// Stage 1: Authentication
// ============================================================================

struct Stage1Controls {
    HWND username;
    HWND password;
};
Stage1Controls g_stage1{};

void create_stage1_panel(HWND panel) {
    int y = 15;

    // Title
    HWND title = CreateWindowExW(0, L"STATIC", L"🔐 Network Authentication Challenge",
                                  WS_CHILD | WS_VISIBLE | SS_CENTER,
                                  20, y, kMainContentWidth - 40, 35, panel, nullptr, g_instance, nullptr);
    if (g_font_title) SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_title), TRUE);
    y += 45;

    // Description
    HWND desc = CreateWindowExW(0, L"STATIC",
                                 L"Authenticate using the network API. Your credentials will be validated\n"
                                 L"via WinHTTP POST and encrypted using BCrypt AES-256.",
                                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 20, y, kMainContentWidth - 40, 50, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(desc, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 60;

    // Hint box
    HWND hint = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC",
                                 L"💡 Server: localhost:5432/api/user_login\n"
                                 L"Encryption: AES-256 | Credentials: admin / ExLoader2025",
                                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 30, y, kMainContentWidth - 60, 45, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(hint, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 60;

    // Username field
    CreateWindowExW(0, L"STATIC", L"Username:",
                    WS_CHILD | WS_VISIBLE,
                    120, y + 3, 100, 24, panel, nullptr, g_instance, nullptr);
    g_stage1.username = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                        230, y, 380, 30, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(g_stage1.username, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 45;

    // Password field
    CreateWindowExW(0, L"STATIC", L"Password:",
                    WS_CHILD | WS_VISIBLE,
                    120, y + 3, 100, 24, panel, nullptr, g_instance, nullptr);
    g_stage1.password = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                        WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                                        230, y, 380, 30, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(g_stage1.password, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 50;

    // Authenticate button
    CreateWindowExW(0, L"BUTTON", L"🚀 Authenticate",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    280, y, 220, 45, panel,
                    reinterpret_cast<HMENU>(ID_BTN_STAGE1), g_instance, nullptr);
    y += 60;

    // Status display
    HWND status = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC", L"Status: Waiting for authentication...",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   40, y, kMainContentWidth - 80, 110, panel,
                                   reinterpret_cast<HMENU>(1001), g_instance, nullptr);
    if (g_font_normal) SendMessageW(status, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
}

void handle_stage1() {
    const std::wstring username = read_text(g_stage1.username);
    const std::wstring password = read_text(g_stage1.password);

    add_telemetry(L"STAGE1", L"Authentication attempt: " + username, modern_ui::colors::info);

    const std::string user_utf8 = narrow_utf8(username);
    const std::string pass_utf8 = narrow_utf8(password);

    // Build JSON payload
    const std::string json_payload = "{\"username\":\"" + user_utf8 + "\",\"password\":\"" + pass_utf8 + "\"}";

    // Encrypt payload with AES-256
    add_telemetry(L"BCrypt", L"Encrypting credentials with AES-256", modern_ui::colors::accent_purple);
    std::vector<uint8_t> payload_bytes(json_payload.begin(), json_payload.end());
    auto key = get_shared_aes_key();
    auto encrypted_payload = test_target::bcrypt_aes_encrypt(payload_bytes, key);
    add_telemetry(L"BCrypt", L"Encryption complete (" + std::to_wstring(encrypted_payload.size()) + L" bytes)", modern_ui::colors::success);

    // Convert to hex string for transmission
    std::string hex_payload;
    hex_payload.reserve(encrypted_payload.size() * 2);
    for (uint8_t byte : encrypted_payload) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex_payload += buf;
    }

    // POST to local server
    add_telemetry(L"WinHTTP", L"POST http://localhost:5432/api/user_login", modern_ui::colors::accent_blue);

    std::string request_body = "{\"encrypted_data\":\"" + hex_payload + "\"}";
    auto response = test_target::winhttp_post("http://localhost:5432/api/user_login", request_body);

    bool auth_ok = false;
    std::string server_message;

    if (response.success) {
        add_telemetry(L"WinHTTP", L"Response: " + std::to_wstring(response.status_code),
                      response.status_code == 200 ? modern_ui::colors::success : modern_ui::colors::error);

        // Parse encrypted response
        size_t data_pos = response.body.find("\"encrypted_data\":\"");
        if (data_pos != std::string::npos) {
            size_t data_start = data_pos + 18;
            size_t data_end = response.body.find("\"", data_start);
            std::string hex_data = response.body.substr(data_start, data_end - data_start);

            add_telemetry(L"BCrypt", L"Decrypting server response with reversed key", modern_ui::colors::accent_purple);

            // Convert hex to bytes
            std::vector<uint8_t> encrypted_bytes;
            for (size_t i = 0; i < hex_data.length(); i += 2) {
                std::string byte_str = hex_data.substr(i, 2);
                encrypted_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            }

            // Decrypt with reversed key
            auto reversed_key = get_reversed_aes_key();
            auto decrypted = test_target::bcrypt_aes_decrypt(encrypted_bytes, reversed_key);

            if (!decrypted.empty()) {
                std::string response_json(decrypted.begin(), decrypted.end());
                add_telemetry(L"BCrypt", L"Server response decrypted successfully", modern_ui::colors::success);

                auth_ok = (response.status_code == 200);

                // Parse JSON response (simple parse)
                size_t msg_pos = response_json.find("\"message\":\"");
                if (msg_pos != std::string::npos) {
                    size_t msg_start = msg_pos + 11;
                    size_t msg_end = response_json.find("\"", msg_start);
                    if (msg_end != std::string::npos) {
                        server_message = response_json.substr(msg_start, msg_end - msg_start);
                    }
                }
            } else {
                add_telemetry(L"BCrypt", L"Failed to decrypt server response", modern_ui::colors::error);
                server_message = "Decryption failed";
            }
        } else {
            server_message = "Invalid server response format";
        }
    } else {
        add_telemetry(L"WinHTTP", L"Request failed", modern_ui::colors::error);
        server_message = "Network error or server not running";
    }

    update_telemetry_display();

    HWND status = GetDlgItem(g_panels[static_cast<int>(StageId::Authentication)], 1001);
    if (auth_ok) {
        SetWindowTextW(status, (L"✅ " + widen_utf8(server_message) + L"\n\nStage 1 Complete.\nStage 2 has been unlocked.").c_str());
        complete_stage(StageId::Authentication);
        MessageBoxW(g_main_window, L"Congratulations! Stage 1 completed.\n\nStage 2: License Validation is now unlocked!",
                    L"Stage 1 Complete", MB_ICONINFORMATION | MB_OK);
    } else {
        SetWindowTextW(status, (L"❌ Authentication Failed\n\n" + widen_utf8(server_message)).c_str());
    }
}

// ============================================================================
// Stage 2: License Validation
// ============================================================================

struct Stage2Controls {
    HWND serial;
    HWND hwid_display;
};
Stage2Controls g_stage2{};

std::wstring generate_hwid() {
    DWORD volume_serial = 0;
    GetVolumeInformationW(L"C:\\", nullptr, 0, &volume_serial, nullptr, nullptr, nullptr, 0);

    wchar_t buf[64];
    swprintf(buf, 64, L"HWID-%08X-%08X", volume_serial, GetTickCount() % 0xFFFFFF);
    return buf;
}

// Sequential cipher: XOR + rotate each byte
std::string apply_sequential_cipher(const std::string& input) {
    std::string output = input;
    uint8_t key = 0x5A;  // Initial XOR key

    for (size_t i = 0; i < output.size(); ++i) {
        // XOR with key
        output[i] ^= key;
        // Rotate bits
        uint8_t byte = static_cast<uint8_t>(output[i]);
        output[i] = static_cast<char>((byte << 3) | (byte >> 5));
        // Update key sequentially
        key = (key + 0x17) ^ static_cast<uint8_t>(i);
    }

    return output;
}

// Generate serial from HWID using sequential cipher + MD5
std::wstring generate_serial_from_hwid(const std::wstring& hwid) {
    // Convert HWID to UTF-8
    std::string hwid_utf8 = narrow_utf8(hwid);

    // Apply sequential cipher
    std::string ciphered = apply_sequential_cipher(hwid_utf8);

    // Calculate MD5 hash
    std::string md5_hash = test_target::bcrypt_md5(ciphered);

    // Format as serial: XXXXX-XXXXX-XXXXX-XXXXX (4 groups of 5, uppercase)
    std::wstring serial;
    for (size_t i = 0; i < 20 && i < md5_hash.size(); ++i) {
        if (i > 0 && i % 5 == 0) {
            serial += L'-';
        }
        serial += static_cast<wchar_t>(std::toupper(md5_hash[i]));
    }

    return serial;
}

bool validate_serial(const std::wstring& serial, const std::wstring& hwid) {
    // Format: XXXXX-XXXXX-XXXXX-XXXXX
    if (serial.size() != 23) return false;  // 20 chars + 3 dashes

    // Generate expected serial from HWID
    std::wstring expected_serial = generate_serial_from_hwid(hwid);

    // Case-insensitive comparison
    std::wstring serial_upper = serial;
    std::transform(serial_upper.begin(), serial_upper.end(), serial_upper.begin(), ::towupper);

    return serial_upper == expected_serial;
}

void create_stage2_panel(HWND panel) {
    int y = 15;

    // Title
    HWND title = CreateWindowExW(0, L"STATIC", L"📜 License Key Validation",
                                  WS_CHILD | WS_VISIBLE | SS_CENTER,
                                  20, y, kMainContentWidth - 40, 35, panel, nullptr, g_instance, nullptr);
    if (g_font_title) SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_title), TRUE);
    y += 45;

    // Description
    HWND desc = CreateWindowExW(0, L"STATIC",
                                 L"Enter a valid license key. The key is bound to your Hardware ID (HWID).\n"
                                 L"The validation uses CryptoAPI (sequential cipher + MD5 hash).",
                                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 20, y, kMainContentWidth - 40, 50, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(desc, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 60;

    // HWID display
    CreateWindowExW(0, L"STATIC", L"Your Hardware ID:",
                    WS_CHILD | WS_VISIBLE,
                    100, y + 3, 150, 24, panel, nullptr, g_instance, nullptr);
    g_stage2.hwid_display = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC", generate_hwid().c_str(),
                                            WS_CHILD | WS_VISIBLE | SS_CENTER,
                                            260, y, 420, 30, panel, nullptr, g_instance, nullptr);
    if (g_font_mono) SendMessageW(g_stage2.hwid_display, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_mono), TRUE);
    y += 45;

    // Hint
    HWND hint = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC",
                                 L"💡 Hint: Serial is generated from HWID using sequential cipher + MD5 hash.\n"
                                 L"Valid format: XXXXX-XXXXX-XXXXX-XXXXX (4 groups, 5 uppercase hex chars each)",
                                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 40, y, kMainContentWidth - 80, 50, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(hint, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 65;

    // Serial input
    CreateWindowExW(0, L"STATIC", L"License Key:",
                    WS_CHILD | WS_VISIBLE,
                    100, y + 3, 120, 24, panel, nullptr, g_instance, nullptr);
    g_stage2.serial = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_UPPERCASE,
                                      230, y, 420, 30, panel, nullptr, g_instance, nullptr);
    if (g_font_normal) SendMessageW(g_stage2.serial, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    y += 45;

    // Validate button
    CreateWindowExW(0, L"BUTTON", L"🔑 Validate License",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    290, y, 220, 45, panel,
                    reinterpret_cast<HMENU>(ID_BTN_STAGE2), g_instance, nullptr);
    y += 60;

    // Status
    HWND status = CreateWindowExW(WS_EX_STATICEDGE, L"STATIC", L"Status: Waiting for license key...",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT,
                                   40, y, kMainContentWidth - 80, 110, panel,
                                   reinterpret_cast<HMENU>(2001), g_instance, nullptr);
    if (g_font_normal) SendMessageW(status, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
}

void handle_stage2() {
    const std::wstring serial = read_text(g_stage2.serial);
    const std::wstring hwid = read_text(g_stage2.hwid_display);

    add_telemetry(L"STAGE2", L"License validation attempt", modern_ui::colors::info);
    add_telemetry(L"STAGE2", L"HWID: " + hwid, modern_ui::colors::info);

    // Generate expected serial for this HWID
    add_telemetry(L"CryptoAPI", L"Applying sequential cipher (XOR+Rotate)", modern_ui::colors::accent_purple);
    std::string hwid_utf8 = narrow_utf8(hwid);
    std::string ciphered = apply_sequential_cipher(hwid_utf8);
    add_telemetry(L"CryptoAPI", L"Sequential cipher complete (" + std::to_wstring(ciphered.size()) + L" bytes)", modern_ui::colors::success);

    // Calculate MD5
    add_telemetry(L"CryptoAPI", L"Computing MD5 hash", modern_ui::colors::accent_purple);
    std::string md5_hash = test_target::bcrypt_md5(ciphered);
    add_telemetry(L"CryptoAPI", L"MD5: " + widen_utf8(md5_hash.substr(0, 20)) + L"...", modern_ui::colors::success);

    // Generate and show expected serial
    std::wstring expected_serial = generate_serial_from_hwid(hwid);
    add_telemetry(L"STAGE2", L"Expected Serial: " + expected_serial, modern_ui::colors::info);
    add_telemetry(L"STAGE2", L"Entered Serial:  " + serial, modern_ui::colors::info);

    // Validate serial (local check only)
    add_telemetry(L"STAGE2", L"Validating license key...", modern_ui::colors::accent_purple);
    bool valid = validate_serial(serial, hwid);

    if (valid) {
        add_telemetry(L"STAGE2", L"License key is VALID!", modern_ui::colors::success);
    } else {
        add_telemetry(L"STAGE2", L"License key is INVALID!", modern_ui::colors::error);
    }

    update_telemetry_display();

    HWND status = GetDlgItem(g_panels[static_cast<int>(StageId::LicenseValidation)], 2001);
    if (valid) {
        SetWindowTextW(status, L"✅ License Valid!\n\nYour license has been activated.\nStage 2 Complete!");
        complete_stage(StageId::LicenseValidation);
        MessageBoxW(g_main_window, L"License activated successfully!\n\nStage 3: File Validation is now unlocked!",
                    L"Stage 2 Complete", MB_ICONINFORMATION | MB_OK);
    } else {
        SetWindowTextW(status, (L"❌ Invalid License Key\n\nThe serial number is invalid or not bound to your HWID.\n\nCorrect serial: " + expected_serial).c_str());
    }
}

// ============================================================================
// Remaining stages (simplified for now)
// ============================================================================

void create_stage3_panel(HWND panel) {
    int y = 30;
    CreateWindowExW(0, L"STATIC", L"🗂️ File Validation Challenge",
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    20, y, kMainContentWidth - 40, 40, panel, nullptr, g_instance, nullptr);
    y += 50;

    CreateWindowExW(0, L"STATIC",
                    L"An offline licence file must be present before the loader continues.\n"
                    L"Only signed artefacts are accepted.",
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    20, y, kMainContentWidth - 40, 60, panel, nullptr, g_instance, nullptr);
    y += 70;

    CreateWindowExW(0, L"BUTTON", L"Validate Licence File",
                    WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                    250, y, 220, 40, panel,
                    reinterpret_cast<HMENU>(ID_BTN_STAGE3), g_instance, nullptr);
    y += 60;

    CreateWindowExW(WS_EX_STATICEDGE, L"STATIC", L"Status: Waiting for file check...",
                    WS_CHILD | WS_VISIBLE | SS_CENTER,
                    60, y, kMainContentWidth - 120, 100, panel,
                    reinterpret_cast<HMENU>(3001), g_instance, nullptr);
}

void handle_stage3() {
    wchar_t module_path[MAX_PATH];
    GetModuleFileNameW(nullptr, module_path, MAX_PATH);
    std::filesystem::path base = std::filesystem::path(module_path).parent_path();
    auto file_path = base / "test_target.licence.dat";
    std::wstring file_path_str = file_path.wstring();

    add_telemetry(L"FILE", L"Validating licence file", modern_ui::colors::info);
    add_telemetry(L"FILE", L"Path: " + file_path_str, modern_ui::colors::info);

    // Check file existence using Win32 API (hookable)
    add_telemetry(L"FILE", L"Checking file attributes...", modern_ui::colors::accent_purple);
    DWORD attrs = GetFileAttributesW(file_path_str.c_str());
    bool exists = (attrs != INVALID_FILE_ATTRIBUTES) && !(attrs & FILE_ATTRIBUTE_DIRECTORY);

    bool signature_ok = false;
    if (exists) {
        add_telemetry(L"FILE", L"File exists, opening for reading", modern_ui::colors::success);

        // Open file using Win32 API (hookable)
        HANDLE hFile = CreateFileW(file_path_str.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile != INVALID_HANDLE_VALUE) {
            add_telemetry(L"FILE", L"File opened successfully", modern_ui::colors::success);

            // Get file size
            DWORD file_size = GetFileSize(hFile, nullptr);
            add_telemetry(L"FILE", L"File size: " + std::to_wstring(file_size) + L" bytes", modern_ui::colors::info);

            if (file_size > 0 && file_size < 1024 * 1024) {  // Max 1MB
                // Read file content using Win32 API (hookable)
                std::vector<char> buffer(file_size);
                DWORD bytes_read = 0;

                add_telemetry(L"FILE", L"Reading file content...", modern_ui::colors::accent_purple);
                if (ReadFile(hFile, buffer.data(), file_size, &bytes_read, nullptr)) {
                    add_telemetry(L"FILE", L"Read " + std::to_wstring(bytes_read) + L" bytes", modern_ui::colors::success);

                    std::string contents(buffer.begin(), buffer.begin() + bytes_read);
                    signature_ok = contents.find("EXLOADER-LICENSE") != std::string::npos;

                    if (signature_ok) {
                        add_telemetry(L"FILE", L"Valid signature found: EXLOADER-LICENSE", modern_ui::colors::success);
                    } else {
                        add_telemetry(L"FILE", L"Invalid signature - expected: EXLOADER-LICENSE", modern_ui::colors::error);
                    }
                } else {
                    add_telemetry(L"FILE", L"Failed to read file content", modern_ui::colors::error);
                }
            } else {
                add_telemetry(L"FILE", L"Invalid file size", modern_ui::colors::error);
            }

            CloseHandle(hFile);
            add_telemetry(L"FILE", L"File closed", modern_ui::colors::info);
        } else {
            add_telemetry(L"FILE", L"Failed to open file for reading", modern_ui::colors::error);
        }
    } else {
        add_telemetry(L"FILE", L"File does not exist", modern_ui::colors::error);
    }

    update_telemetry_display();

    HWND status = GetDlgItem(g_panels[static_cast<int>(StageId::TimeBomb)], 3001);
    if (exists && signature_ok) {
        SetWindowTextW(status, (L"✅ File found at: " + file_path_str + L"\n\nValid signature detected.\nStage 3 Complete!").c_str());
        complete_stage(StageId::TimeBomb);
        MessageBoxW(g_main_window,
                    L"🎉 CONGRATULATIONS!\n\nYou've completed all stages of the ExLoader CrackMe!\n\n"
                    L"All hook instrumentation points have been demonstrated:\n"
                    L"✅ Network Authentication (WinHTTP + BCrypt AES)\n"
                    L"✅ License Validation (CryptoAPI MD5 + Sequential Cipher)\n"
                    L"✅ File Validation (CreateFile + ReadFile + GetFileAttributes)",
                    L"All Stages Complete!", MB_ICONINFORMATION | MB_OK);
    } else {
        std::wstring message = exists
            ? L"❌ Licence file found but invalid signature.\n\nThe file must contain the signature: EXLOADER-LICENSE"
            : L"❌ Licence file not found.\n\nPlease create test_target.licence.dat next to the EXE.";
        SetWindowTextW(status, message.c_str());
    }
}

// ============================================================================
// Panel Window Class
// ============================================================================

constexpr wchar_t kPanelClassName[] = L"ExLoaderCrackMePanel";

LRESULT CALLBACK PanelWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_COMMAND:
        case WM_NOTIFY:
            // Forward to main window
            if (g_main_window) {
                return SendMessageW(g_main_window, msg, wparam, lparam);
            }
            break;
        case WM_CTLCOLORSTATIC:
            // Dark theme for static controls
            SetBkMode(reinterpret_cast<HDC>(wparam), TRANSPARENT);
            SetTextColor(reinterpret_cast<HDC>(wparam), kColorText);
            return reinterpret_cast<LRESULT>(g_brush_panel);
        case WM_CTLCOLOREDIT:
            // Dark theme for edit controls
            SetBkColor(reinterpret_cast<HDC>(wparam), kColorBackground);
            SetTextColor(reinterpret_cast<HDC>(wparam), kColorText);
            return reinterpret_cast<LRESULT>(g_brush_background);
        case WM_ERASEBKGND:
            // Paint panel background
            {
                HDC hdc = reinterpret_cast<HDC>(wparam);
                RECT rc;
                GetClientRect(hwnd, &rc);
                FillRect(hdc, &rc, g_brush_panel);
                return 1;
            }
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

// ============================================================================
// Main Window
// ============================================================================

void show_panel(StageId id) {
    for (int i = 0; i < static_cast<int>(StageId::COUNT); ++i) {
        ShowWindow(g_panels[i], (i == static_cast<int>(id)) ? SW_SHOW : SW_HIDE);
    }
    // Force repaint
    if (g_main_window) {
        InvalidateRect(g_main_window, nullptr, TRUE);
        UpdateWindow(g_main_window);
    }
}

void init_tabs(HWND parent) {
    g_tab = CreateWindowExW(0, WC_TABCONTROLW, L"",
                            WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | WS_VISIBLE,
                            15, 15, kMainContentWidth - 10, kWindowHeight - 70, parent,
                            reinterpret_cast<HMENU>(ID_TAB), g_instance, nullptr);

    for (size_t i = 0; i < g_stages.size(); ++i) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        std::wstring tab_text = g_stages[i].unlocked
            ? (g_stages[i].completed ? L"✅ " : L"🔓 ") + g_stages[i].title
            : L"🔒 " + g_stages[i].title;
        item.pszText = const_cast<LPWSTR>(tab_text.c_str());
        TabCtrl_InsertItem(g_tab, static_cast<int>(i), &item);
    }

    // Get tab display area (inside the tab control, below the tabs)
    RECT tab_rect;
    GetClientRect(g_tab, &tab_rect);
    TabCtrl_AdjustRect(g_tab, FALSE, &tab_rect);

    // Create panels as children of the tab control
    int panel_x = tab_rect.left;
    int panel_y = tab_rect.top;
    int panel_width = tab_rect.right - tab_rect.left;
    int panel_height = tab_rect.bottom - tab_rect.top;

    for (int i = 0; i < static_cast<int>(StageId::COUNT); ++i) {
        g_panels[i] = CreateWindowExW(0, kPanelClassName, L"",
                                      WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                                      panel_x, panel_y, panel_width, panel_height,
                                      g_tab, nullptr, g_instance, nullptr);
    }

    create_stage1_panel(g_panels[0]);
    create_stage2_panel(g_panels[1]);
    create_stage3_panel(g_panels[2]);

    show_panel(StageId::Authentication);
}

void init_telemetry_panel(HWND parent) {
    // Title
    HWND title = CreateWindowExW(0, L"STATIC", L"📊 Live Telemetry (ExLoader Hooks)",
                                  WS_CHILD | WS_VISIBLE | SS_CENTER,
                                  kWindowWidth - kTelemetryWidth - 10, 10,
                                  kTelemetryWidth, 25, parent, nullptr, g_instance, nullptr);
    if (g_font_normal) {
        SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_normal), TRUE);
    }

    // Log box (multiline edit for now, could use RichEdit)
    g_telemetry_box = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                      kWindowWidth - kTelemetryWidth - 15, 50,
                                      kTelemetryWidth - 10, kWindowHeight - 90, parent,
                                      reinterpret_cast<HMENU>(ID_TELEMETRY_LOG), g_instance, nullptr);

    if (g_font_mono) {
        SendMessageW(g_telemetry_box, WM_SETFONT, reinterpret_cast<WPARAM>(g_font_mono), TRUE);
    }

    add_telemetry(L"SYSTEM", L"ExLoader CrackMe initialized", modern_ui::colors::success);
    add_telemetry(L"SYSTEM", L"Hook instrumentation active", modern_ui::colors::info);
    update_telemetry_display();
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_COMMAND: {
            int id = LOWORD(wparam);
            switch (id) {
                case ID_BTN_STAGE1: handle_stage1(); break;
                case ID_BTN_STAGE2: handle_stage2(); break;
                case ID_BTN_STAGE3: handle_stage3(); break;
            }
            // Update tab labels after stage completion
            for (size_t i = 0; i < g_stages.size(); ++i) {
                TCITEMW item{};
                item.mask = TCIF_TEXT;
                std::wstring tab_text = g_stages[i].unlocked
                    ? (g_stages[i].completed ? L"✅ " : L"🔓 ") + g_stages[i].title
                    : L"🔒 " + g_stages[i].title;
                item.pszText = const_cast<LPWSTR>(tab_text.c_str());
                TabCtrl_SetItem(g_tab, static_cast<int>(i), &item);
            }
            break;
        }
        case WM_NOTIFY: {
            if (reinterpret_cast<LPNMHDR>(lparam)->idFrom == ID_TAB &&
                reinterpret_cast<LPNMHDR>(lparam)->code == TCN_SELCHANGE) {
                int selected = TabCtrl_GetCurSel(g_tab);
                if (selected >= 0 && selected < static_cast<int>(StageId::COUNT)) {
                    g_current_stage = static_cast<StageId>(selected);
                    show_panel(g_current_stage);
                }
            }
            break;
        }
        case WM_TIMER: {
            // Update telemetry display periodically (every 100ms)
            update_telemetry_display();
            break;
        }
        case WM_CTLCOLORSTATIC:
            // Dark theme for static controls in main window
            SetBkMode(reinterpret_cast<HDC>(wparam), TRANSPARENT);
            SetTextColor(reinterpret_cast<HDC>(wparam), kColorText);
            return reinterpret_cast<LRESULT>(g_brush_background);
        case WM_CTLCOLOREDIT:
            // Dark theme for edit controls (telemetry box)
            SetBkColor(reinterpret_cast<HDC>(wparam), kColorBackground);
            SetTextColor(reinterpret_cast<HDC>(wparam), kColorText);
            return reinterpret_cast<LRESULT>(g_brush_background);
        case WM_ERASEBKGND:
            // Paint main window background
            {
                HDC hdc = reinterpret_cast<HDC>(wparam);
                RECT rc;
                GetClientRect(hwnd, &rc);
                FillRect(hdc, &rc, g_brush_background);
                return 1;
            }
        case WM_DESTROY:
            KillTimer(hwnd, 1);
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    return 0;
}

}  // namespace

// ============================================================================
// Public Entry Point
// ============================================================================

void run_gui_login_demo() {
    g_instance = GetModuleHandleW(nullptr);

    LoadLibraryW(L"Msftedit.dll");

    INITCOMMONCONTROLSEX icc{sizeof(INITCOMMONCONTROLSEX), ICC_TAB_CLASSES};
    InitCommonControlsEx(&icc);

    // Initialize HTTP server
    g_http_server = std::make_unique<SimpleHttpServer>(5432);

    // Register /api/user_login handler
    g_http_server->add_handler("/api/user_login", [](const ServerHttpRequest& req) -> ServerHttpResponse {
        ServerHttpResponse resp;
        resp.headers["Content-Type"] = "application/json";

        add_telemetry(L"SERVER", L"Received /api/user_login request", modern_ui::colors::info);

        // Parse JSON request body
        size_t data_pos = req.body.find("\"encrypted_data\":\"");
        if (data_pos == std::string::npos) {
            resp.status_code = 400;
            resp.status_text = "Bad Request";
            resp.body = "{\"success\":false,\"message\":\"Missing encrypted_data\"}";
            add_telemetry(L"SERVER", L"Bad request: missing encrypted_data", modern_ui::colors::error);
            return resp;
        }

        size_t data_start = data_pos + 18;
        size_t data_end = req.body.find("\"", data_start);
        std::string hex_data = req.body.substr(data_start, data_end - data_start);

        // Convert hex to bytes
        std::vector<uint8_t> encrypted_bytes;
        for (size_t i = 0; i < hex_data.length(); i += 2) {
            std::string byte_str = hex_data.substr(i, 2);
            encrypted_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }

        add_telemetry(L"SERVER", L"Decrypting payload with AES-256", modern_ui::colors::accent_purple);

        // Decrypt with shared key
        auto key = get_shared_aes_key();
        auto decrypted = test_target::bcrypt_aes_decrypt(encrypted_bytes, key);

        if (decrypted.empty()) {
            resp.status_code = 500;
            resp.status_text = "Internal Server Error";
            resp.body = "{\"success\":false,\"message\":\"Decryption failed\"}";
            add_telemetry(L"SERVER", L"Decryption failed", modern_ui::colors::error);
            return resp;
        }

        std::string json_payload(decrypted.begin(), decrypted.end());
        add_telemetry(L"SERVER", L"Decryption successful", modern_ui::colors::success);

        // Parse username and password from JSON
        size_t user_pos = json_payload.find("\"username\":\"");
        size_t pass_pos = json_payload.find("\"password\":\"");

        if (user_pos == std::string::npos || pass_pos == std::string::npos) {
            resp.status_code = 400;
            resp.status_text = "Bad Request";
            resp.body = "{\"success\":false,\"message\":\"Invalid JSON format\"}";
            return resp;
        }

        size_t user_start = user_pos + 12;
        size_t user_end = json_payload.find("\"", user_start);
        std::string username = json_payload.substr(user_start, user_end - user_start);

        size_t pass_start = pass_pos + 12;
        size_t pass_end = json_payload.find("\"", pass_start);
        std::string password = json_payload.substr(pass_start, pass_end - pass_start);

        add_telemetry(L"SERVER", L"Validating credentials: " + widen_utf8(username), modern_ui::colors::info);

        // Build response JSON (plaintext first)
        std::string response_json;
        if (username == "admin" && password == "ExLoader2025") {
            resp.status_code = 200;
            resp.status_text = "OK";
            response_json = "{\"success\":true,\"message\":\"Authentication successful\",\"token\":\"eyJhbGciOiJIUzI1NiJ9.dGVzdA.test\"}";
            add_telemetry(L"SERVER", L"Authentication SUCCESS", modern_ui::colors::success);
        } else {
            resp.status_code = 401;
            resp.status_text = "Unauthorized";
            response_json = "{\"success\":false,\"message\":\"Invalid username or password\"}";
            add_telemetry(L"SERVER", L"Authentication FAILED: invalid credentials", modern_ui::colors::error);
        }

        // Encrypt response with reversed key
        add_telemetry(L"SERVER", L"Encrypting response with reversed AES-256 key", modern_ui::colors::accent_purple);
        std::vector<uint8_t> response_bytes(response_json.begin(), response_json.end());
        auto reversed_key = get_reversed_aes_key();
        auto encrypted_response = test_target::bcrypt_aes_encrypt(response_bytes, reversed_key);

        // Convert to hex
        std::string hex_response;
        hex_response.reserve(encrypted_response.size() * 2);
        for (uint8_t byte : encrypted_response) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_response += buf;
        }

        resp.body = "{\"encrypted_data\":\"" + hex_response + "\"}";
        add_telemetry(L"SERVER", L"Encrypted response ready (" + std::to_wstring(encrypted_response.size()) + L" bytes)", modern_ui::colors::success);

        // NOTE: Do NOT call update_telemetry_display() here!
        // Server runs on background thread, GUI updates must be on main thread
        // Telemetry display will be updated by timer
        return resp;
    });

    // Register /api/validate_license handler
    g_http_server->add_handler("/api/validate_license", [](const ServerHttpRequest& req) -> ServerHttpResponse {
        ServerHttpResponse resp;
        resp.headers["Content-Type"] = "application/json";

        add_telemetry(L"SERVER", L"Received /api/validate_license request", modern_ui::colors::info);

        // Parse encrypted request
        size_t data_pos = req.body.find("\"encrypted_data\":\"");
        if (data_pos == std::string::npos) {
            resp.status_code = 400;
            resp.status_text = "Bad Request";
            resp.body = "{\"encrypted_data\":\"" + std::string() + "\"}";
            add_telemetry(L"SERVER", L"Bad request: missing encrypted_data", modern_ui::colors::error);
            return resp;
        }

        size_t data_start = data_pos + 18;
        size_t data_end = req.body.find("\"", data_start);
        std::string hex_data = req.body.substr(data_start, data_end - data_start);

        // Convert hex to bytes
        std::vector<uint8_t> encrypted_bytes;
        for (size_t i = 0; i < hex_data.length(); i += 2) {
            std::string byte_str = hex_data.substr(i, 2);
            encrypted_bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }

        add_telemetry(L"SERVER", L"Decrypting license request", modern_ui::colors::accent_purple);

        // Decrypt with shared key
        auto key = get_shared_aes_key();
        auto decrypted = test_target::bcrypt_aes_decrypt(encrypted_bytes, key);

        if (decrypted.empty()) {
            resp.status_code = 500;
            resp.status_text = "Internal Server Error";
            std::string error_json = "{\"success\":false,\"message\":\"Decryption failed\"}";
            std::vector<uint8_t> error_bytes(error_json.begin(), error_json.end());
            auto reversed_key = get_reversed_aes_key();
            auto encrypted_error = test_target::bcrypt_aes_encrypt(error_bytes, reversed_key);
            std::string hex_error;
            for (uint8_t byte : encrypted_error) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", byte);
                hex_error += buf;
            }
            resp.body = "{\"encrypted_data\":\"" + hex_error + "\"}";
            add_telemetry(L"SERVER", L"Decryption failed", modern_ui::colors::error);
            return resp;
        }

        std::string request_json(decrypted.begin(), decrypted.end());
        add_telemetry(L"SERVER", L"Request decrypted successfully", modern_ui::colors::success);

        // Parse serial and HWID
        size_t serial_pos = request_json.find("\"serial\":\"");
        size_t hwid_pos = request_json.find("\"hwid\":\"");

        if (serial_pos == std::string::npos || hwid_pos == std::string::npos) {
            resp.status_code = 400;
            resp.status_text = "Bad Request";
            std::string error_json = "{\"success\":false,\"message\":\"Invalid request format\"}";
            std::vector<uint8_t> error_bytes(error_json.begin(), error_json.end());
            auto reversed_key = get_reversed_aes_key();
            auto encrypted_error = test_target::bcrypt_aes_encrypt(error_bytes, reversed_key);
            std::string hex_error;
            for (uint8_t byte : encrypted_error) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", byte);
                hex_error += buf;
            }
            resp.body = "{\"encrypted_data\":\"" + hex_error + "\"}";
            return resp;
        }

        size_t serial_start = serial_pos + 10;
        size_t serial_end = request_json.find("\"", serial_start);
        std::string serial = request_json.substr(serial_start, serial_end - serial_start);

        size_t hwid_start = hwid_pos + 8;
        size_t hwid_end = request_json.find("\"", hwid_start);
        std::string hwid = request_json.substr(hwid_start, hwid_end - hwid_start);

        add_telemetry(L"SERVER", L"Validating license for HWID: " + widen_utf8(hwid), modern_ui::colors::info);

        // Generate expected serial from HWID
        std::wstring hwid_wide = widen_utf8(hwid);
        std::wstring expected_serial = generate_serial_from_hwid(hwid_wide);
        std::string expected_serial_utf8 = narrow_utf8(expected_serial);

        add_telemetry(L"SERVER", L"Expected: " + expected_serial, modern_ui::colors::info);
        add_telemetry(L"SERVER", L"Received: " + widen_utf8(serial), modern_ui::colors::info);

        // Validate (case-insensitive)
        std::string serial_upper = serial;
        std::transform(serial_upper.begin(), serial_upper.end(), serial_upper.begin(), ::toupper);
        std::transform(expected_serial_utf8.begin(), expected_serial_utf8.end(), expected_serial_utf8.begin(), ::toupper);

        // Build response JSON
        std::string response_json;
        if (serial_upper == expected_serial_utf8) {
            resp.status_code = 200;
            resp.status_text = "OK";
            response_json = "{\"success\":true,\"message\":\"License validated successfully\",\"hwid\":\"" + hwid + "\"}";
            add_telemetry(L"SERVER", L"License VALID", modern_ui::colors::success);
        } else {
            resp.status_code = 401;
            resp.status_text = "Unauthorized";
            response_json = "{\"success\":false,\"message\":\"Invalid license key\",\"expected\":\"" + expected_serial_utf8 + "\"}";
            add_telemetry(L"SERVER", L"License INVALID", modern_ui::colors::error);
        }

        // Encrypt response with reversed key
        add_telemetry(L"SERVER", L"Encrypting response with reversed key", modern_ui::colors::accent_purple);
        std::vector<uint8_t> response_bytes(response_json.begin(), response_json.end());
        auto reversed_key = get_reversed_aes_key();
        auto encrypted_response = test_target::bcrypt_aes_encrypt(response_bytes, reversed_key);

        // Convert to hex
        std::string hex_response;
        hex_response.reserve(encrypted_response.size() * 2);
        for (uint8_t byte : encrypted_response) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_response += buf;
        }

        resp.body = "{\"encrypted_data\":\"" + hex_response + "\"}";
        add_telemetry(L"SERVER", L"Response encrypted and ready", modern_ui::colors::success);

        return resp;
    });

    // Start server
    if (g_http_server->start()) {
        add_telemetry(L"SYSTEM", L"HTTP server started on port 5432", modern_ui::colors::success);
    } else {
        add_telemetry(L"SYSTEM", L"Failed to start HTTP server", modern_ui::colors::error);
    }

    // Create theme brushes
    g_brush_background = CreateSolidBrush(kColorBackground);
    g_brush_panel = CreateSolidBrush(kColorPanel);

    // Create fonts
    g_font_title = CreateFontW(-24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_font_normal = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_font_mono = CreateFontW(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

    // Register main window class
    WNDCLASSW wc{};
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = L"ExLoaderCrackMe";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = g_brush_background;
    RegisterClassW(&wc);

    // Register panel window class
    WNDCLASSW panel_wc{};
    panel_wc.style = CS_HREDRAW | CS_VREDRAW;
    panel_wc.lpfnWndProc = PanelWndProc;
    panel_wc.hInstance = g_instance;
    panel_wc.lpszClassName = kPanelClassName;
    panel_wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    panel_wc.hbrBackground = g_brush_panel;
    RegisterClassW(&panel_wc);

    g_main_window = CreateWindowExW(WS_EX_OVERLAPPEDWINDOW, wc.lpszClassName,
                                    L"ExLoader CrackMe - Multi-Stage Challenge",
                                    (WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME)) | WS_CLIPCHILDREN,
                                    CW_USEDEFAULT, CW_USEDEFAULT, kWindowWidth, kWindowHeight,
                                    nullptr, nullptr, g_instance, nullptr);

    init_tabs(g_main_window);
    init_telemetry_panel(g_main_window);

    ShowWindow(g_main_window, SW_SHOWNORMAL);
    UpdateWindow(g_main_window);

    // Start timer for telemetry display updates (100ms interval)
    SetTimer(g_main_window, 1, 100, nullptr);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Stop server
    if (g_http_server) {
        g_http_server->stop();
        add_telemetry(L"SYSTEM", L"HTTP server stopped", modern_ui::colors::info);
    }

    DeleteObject(g_font_title);
    DeleteObject(g_font_normal);
    DeleteObject(g_font_mono);
    DeleteObject(g_brush_background);
    DeleteObject(g_brush_panel);
}

}  // namespace test_target
