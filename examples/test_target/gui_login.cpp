#include "gui_login.hpp"

#include "http_operations.hpp"
#include "crypto_operations.hpp"
#include "network_operations.hpp"

#include <windows.h>
#include <commctrl.h>

#include <string>
#include <vector>
#include <cstdio>
#include <cwctype>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")

namespace test_target {

namespace {

enum class TabIndex : int {
    Login = 0,
    Serial = 1,
    Clock = 2,
    Integrity = 3
};

constexpr int kTabControlId = 400;
constexpr int kBtnLogin     = 401;
constexpr int kBtnSerial    = 402;
constexpr int kBtnClock     = 403;
constexpr int kBtnIntegrity = 404;

struct LoginControls {
    HWND user;
    HWND pass;
};

struct SerialControls {
    HWND serial;
};

struct ClockControls {
    HWND current_label;
    HWND status_label;
};

struct IntegrityControls {
    HWND status_label;
};

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
HWND g_tab = nullptr;
HWND g_panels[4]{};

LoginControls g_login{};
SerialControls g_serial{};
ClockControls g_clock{};
IntegrityControls g_integrity{};

const SYSTEMTIME kExpectedUtc = {2025, 11, 0, 9, 9, 0, 0, 0};  // Year, Month(=11), DayOfWeek ignored.

std::wstring format_system_time(const SYSTEMTIME& st) {
    wchar_t buffer[64];
    swprintf(buffer, 64, L"%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buffer;
}

std::wstring read_text(HWND edit) {
    const int len = GetWindowTextLengthW(edit);
    std::wstring text(static_cast<size_t>(len), L'\0');
    GetWindowTextW(edit, text.data(), len + 1);
    return text;
}

std::string narrow_utf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                                          static_cast<int>(text.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(size_needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
                        static_cast<int>(text.size()),
                        result.data(), size_needed, nullptr, nullptr);
    return result;
}

std::wstring widen_from_utf8(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                                          static_cast<int>(text.size()),
                                          nullptr, 0);
    if (size_needed <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(size_needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(),
                        static_cast<int>(text.size()),
                        result.data(), size_needed);
    return result;
}

std::vector<uint8_t> default_key_material() {
    return {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
}

std::wstring format_hex_preview(const std::vector<uint8_t>& data, size_t max_len = 24) {
    std::wstringstream ss;
    size_t count = std::min(max_len, data.size());
    for (size_t i = 0; i < count; ++i) {
        ss << std::hex << std::uppercase;
        ss.width(2);
        ss.fill(L'0');
        ss << static_cast<int>(data[i]) << L' ';
    }
    if (data.size() > max_len) {
        ss << L"...";
    }
    return ss.str();
}

void handle_login(HWND hwnd) {
    const std::wstring username = read_text(g_login.user);
    const std::wstring password = read_text(g_login.pass);
    const bool creds_ok = (username == L"testuser" && password == L"secret123");

    const std::string user_utf8 = narrow_utf8(username);
    const std::string pass_utf8 = narrow_utf8(password);
    const std::string payload =
        std::string("{\"username\":\"") + user_utf8 + "\",\"password\":\"" + pass_utf8 + "\"}";

    const auto http_response = test_target::winhttp_post("https://httpbin.org/post", payload);

    const auto key = default_key_material();
    std::vector<uint8_t> password_bytes(pass_utf8.begin(), pass_utf8.end());
    const auto encrypted = test_target::bcrypt_aes_encrypt(password_bytes, key);
    const auto decrypted = test_target::bcrypt_aes_decrypt(encrypted, key);
    const bool crypto_ok = (decrypted == password_bytes);

    std::wstringstream summary;
    summary << L"Credentials: " << (creds_ok ? L"accepted" : L"rejected") << L"\n";
    summary << L"WinHTTP POST: "
            << (http_response.success ? L"OK (" : L"Failed (status ")
            << http_response.status_code << L")\n";
    if (http_response.success && !http_response.body.empty()) {
        const std::string snippet = http_response.body.substr(0, 80);
        summary << L"Response snippet: " << widen_from_utf8(snippet) << L"\n";
    }
    summary << L"BCrypt AES verification: " << (crypto_ok ? L"match" : L"mismatch")
            << L"\nEncrypted preview: " << format_hex_preview(encrypted);

    const std::wstring login_message = summary.str();
    MessageBoxW(hwnd, login_message.c_str(), L"Auth Simulation",
                creds_ok ? MB_ICONINFORMATION : MB_ICONERROR);
}

bool validate_serial_format(const std::wstring& serial) {
    if (serial.size() != 11) {
        return false;
    }
    for (size_t i = 0; i < serial.size(); ++i) {
        if (i == 3 || i == 7) {
            if (serial[i] != L'-') return false;
            continue;
        }
        if (!iswalnum(serial[i])) return false;
    }
    return true;
}

bool verify_serial_checksum(const std::wstring& serial) {
    int sum = 0;
    for (wchar_t ch : serial) {
        if (ch == L'-') continue;
        sum += static_cast<unsigned char>(ch);
    }
    return (sum % 37) == 13;
}

void handle_serial(HWND hwnd) {
    const std::wstring serial = read_text(g_serial.serial);
    if (!validate_serial_format(serial)) {
        MessageBoxW(hwnd, L"Serial must look like ABC-123-XYZ", L"Serial", MB_ICONWARNING | MB_OK);
        return;
    }
    const bool checksum_ok = verify_serial_checksum(serial);

    const std::string serial_utf8 = narrow_utf8(serial);
    std::vector<uint8_t> serial_bytes(serial_utf8.begin(), serial_utf8.end());
    const auto key = default_key_material();
    const auto enc = test_target::cryptoapi_aes_encrypt(serial_bytes, key);
    const auto dec = test_target::cryptoapi_aes_decrypt(enc, key);
    const bool crypto_ok = (dec == serial_bytes);

    const std::string payload =
        std::string("{\"serial\":\"") + serial_utf8 + "\",\"checksum_ok\":" +
        (checksum_ok ? "true" : "false") + "}";
    const auto response = test_target::wininet_post("https://httpbin.org/post", payload);

    std::wstringstream summary;
    summary << L"Format: OK\nChecksum: " << (checksum_ok ? L"passed" : L"failed") << L"\n";
    summary << L"CryptoAPI AES: " << (crypto_ok ? L"round-trip success" : L"mismatch") << L"\n";
    summary << L"Cipher preview: " << format_hex_preview(enc) << L"\n";
    summary << L"WinInet POST: " << (response.success ? L"200 OK" : L"failed");

    const std::wstring serial_message = summary.str();
    MessageBoxW(hwnd, serial_message.c_str(), L"Serial Validation",
                (checksum_ok && crypto_ok && response.success) ? MB_ICONINFORMATION : MB_ICONERROR);
}

std::wstring clock_status_text(bool ok, long diff_minutes) {
    wchar_t buffer[128];
    swprintf(buffer, 128, L"Offset: %ld minute(s) (%ls)",
             diff_minutes, ok ? L"OK" : L"Too far");
    return buffer;
}

void handle_clock(HWND hwnd) {
    SYSTEMTIME now{};
    GetSystemTime(&now);

    FILETIME ft_now{}, ft_expected{};
    SystemTimeToFileTime(&now, &ft_now);
    SystemTimeToFileTime(&kExpectedUtc, &ft_expected);

    ULARGE_INTEGER a{}, b{};
    a.LowPart = ft_now.dwLowDateTime;
    a.HighPart = ft_now.dwHighDateTime;
    b.LowPart = ft_expected.dwLowDateTime;
    b.HighPart = ft_expected.dwHighDateTime;

    LONGLONG diff = static_cast<LONGLONG>(a.QuadPart) - static_cast<LONGLONG>(b.QuadPart);
    if (diff < 0) diff = -diff;
    long diff_minutes = static_cast<long>(diff / 600000000LL);  // 100ns units -> minutes

    SetWindowTextW(g_clock.current_label, format_system_time(now).c_str());
    const bool ok = diff_minutes <= 5;
    SetWindowTextW(g_clock.status_label, clock_status_text(ok, diff_minutes).c_str());

    auto remote = test_target::wininet_get("https://worldtimeapi.org/api/timezone/Etc/UTC");
    std::wstring remote_info = remote.success
        ? widen_from_utf8(remote.body.substr(0, 80))
        : L"(failed to query service)";

    std::wstringstream summary;
    summary << (ok ? L"System clock looks good." : L"Clock drift detected!") << L"\n";
    summary << L"Offset: " << diff_minutes << L" minute(s)\n";
    summary << L"Remote time sample: " << remote_info;

    const std::wstring clock_message = summary.str();
    MessageBoxW(hwnd, clock_message.c_str(),
                L"Clock validation",
                ok ? (MB_ICONINFORMATION | MB_OK) : (MB_ICONWARNING | MB_OK));
}

bool compute_integrity_digest(std::wstring& status_out, unsigned long long* digest_out = nullptr) {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) {
        status_out = L"GetModuleFileName failed.";
        return false;
    }

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        status_out = L"Cannot open executable.";
        return false;
    }

    std::vector<unsigned char> buffer(64 * 1024);
    DWORD read = 0;
    unsigned long long digest = 0;
    while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) && read > 0) {
        for (DWORD i = 0; i < read; ++i) {
            digest = (digest + buffer[i]) % 0xFFFFFFFFULL;
        }
    }
    CloseHandle(file);

    const bool ok = (digest % 97ULL) == 42ULL;
    wchar_t msg[128];
    swprintf(msg, 128, L"Digest: %llu (mod 97 == %llu)", digest, digest % 97ULL);
    status_out = msg;
    if (digest_out) {
        *digest_out = digest;
    }
    return ok;
}

void handle_integrity(HWND hwnd) {
    std::wstring status;
    unsigned long long digest_value = 0;
    const bool digest_ok = compute_integrity_digest(status, &digest_value);
    SetWindowTextW(g_integrity.status_label, status.c_str());

    const bool socket_ok = test_target::winsock_connect_test("httpbin.org", 80);
    const bool proxy_ok = test_target::test_proxy_settings();

    const std::string hash_input = "digest:" + std::to_string(digest_value);
    const std::string digest_hash = test_target::bcrypt_sha256(hash_input);

    const std::string download_path = "crackme_telemetry.txt";
    const bool download_ok = test_target::urlmon_download("https://httpbin.org/robots.txt", download_path);
    if (download_ok) {
        DeleteFileW(L"crackme_telemetry.txt");
    }

    std::wstringstream summary;
    summary << L"Integrity digest: " << status << L"\n";
    summary << L"Winsock probe: " << (socket_ok ? L"reachable" : L"failed") << L"\n";
    summary << L"Proxy query: " << (proxy_ok ? L"queried" : L"failed") << L"\n";
    summary << L"URLMon download: " << (download_ok ? L"success" : L"failed") << L"\n";
    summary << L"SHA256(digest): " << widen_from_utf8(digest_hash.substr(0, 32)) << L"...";

    MessageBoxW(hwnd,
                digest_ok ? L"Integrity check passed." : L"Integrity mismatch!",
                L"Integrity",
                digest_ok ? (MB_ICONINFORMATION | MB_OK) : (MB_ICONERROR | MB_OK));
    const std::wstring integrity_message = summary.str();
    MessageBoxW(hwnd, integrity_message.c_str(), L"Integrity telemetry", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK PanelSubclassProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam,
                                   UINT_PTR, DWORD_PTR) {
    switch (msg) {
        case WM_COMMAND:
        case WM_NOTIFY:
            if (g_main_window) {
                return SendMessageW(g_main_window, msg, wparam, lparam);
            }
            break;
        default:
            break;
    }
    return DefSubclassProc(hwnd, msg, wparam, lparam);
}

HWND create_panel(HWND parent) {
    HWND panel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
                                 10, 50, 460, 220, parent, nullptr, g_instance, nullptr);
    if (panel) {
        SetWindowSubclass(panel, PanelSubclassProc, 0, 0);
    }
    return panel;
}

void create_login_panel(HWND panel) {
    CreateWindowExW(0, L"STATIC", L"Username:", WS_CHILD | WS_VISIBLE,
                    15, 15, 80, 20, panel, nullptr, g_instance, nullptr);
    g_login.user = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"testuser",
                                   WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                   110, 12, 220, 24, panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Password:", WS_CHILD | WS_VISIBLE,
                    15, 55, 80, 20, panel, nullptr, g_instance, nullptr);
    g_login.pass = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"secret123",
                                   WS_CHILD | WS_VISIBLE | ES_PASSWORD | ES_AUTOHSCROLL,
                                   110, 52, 220, 24, panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Login", WS_CHILD | WS_VISIBLE,
                    350, 32, 80, 30, panel, reinterpret_cast<HMENU>(kBtnLogin), g_instance, nullptr);
}

void create_serial_panel(HWND panel) {
    CreateWindowExW(0, L"STATIC", L"Serial (AAA-111-BBB):", WS_CHILD | WS_VISIBLE,
                    15, 15, 160, 20, panel, nullptr, g_instance, nullptr);
    g_serial.serial = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"ABC-123-XYZ",
                                      WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                      190, 12, 200, 24, panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Validate", WS_CHILD | WS_VISIBLE,
                    350, 42, 80, 28, panel, reinterpret_cast<HMENU>(kBtnSerial), g_instance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Checksum rule: sum(chars) % 37 == 13.",
                    WS_CHILD | WS_VISIBLE, 15, 70, 350, 20, panel, nullptr, g_instance, nullptr);
}

void create_clock_panel(HWND panel) {
    CreateWindowExW(0, L"STATIC", L"Current UTC:", WS_CHILD | WS_VISIBLE,
                    15, 15, 100, 20, panel, nullptr, g_instance, nullptr);
    g_clock.current_label = CreateWindowExW(0, L"STATIC", L"(not checked)",
                                            WS_CHILD | WS_VISIBLE, 130, 15, 250, 20,
                                            panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Expected UTC:", WS_CHILD | WS_VISIBLE,
                    15, 45, 100, 20, panel, nullptr, g_instance, nullptr);
    CreateWindowExW(0, L"STATIC", format_system_time(kExpectedUtc).c_str(),
                    WS_CHILD | WS_VISIBLE, 130, 45, 250, 20,
                    panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Status:", WS_CHILD | WS_VISIBLE,
                    15, 80, 100, 20, panel, nullptr, g_instance, nullptr);
    g_clock.status_label = CreateWindowExW(0, L"STATIC", L"(not checked)",
                                           WS_CHILD | WS_VISIBLE, 130, 80, 250, 20,
                                           panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Validate Clock", WS_CHILD | WS_VISIBLE,
                    15, 120, 140, 30, panel, reinterpret_cast<HMENU>(kBtnClock), g_instance, nullptr);
}

void create_integrity_panel(HWND panel) {
    CreateWindowExW(0, L"STATIC",
                    L"Verifies executable checksum (digest % 97 == 42).",
                    WS_CHILD | WS_VISIBLE, 15, 15, 360, 20,
                    panel, nullptr, g_instance, nullptr);

    g_integrity.status_label = CreateWindowExW(0, L"STATIC", L"(not checked)",
                                               WS_CHILD | WS_VISIBLE, 15, 50, 360, 20,
                                               panel, nullptr, g_instance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Run Integrity Check",
                    WS_CHILD | WS_VISIBLE, 15, 80, 160, 30,
                    panel, reinterpret_cast<HMENU>(kBtnIntegrity), g_instance, nullptr);
}

void show_panel(TabIndex index) {
    for (int i = 0; i < 4; ++i) {
        ShowWindow(g_panels[i], (i == static_cast<int>(index)) ? SW_SHOW : SW_HIDE);
    }
}

void init_tabs(HWND parent) {
    g_tab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
                            10, 10, 460, 260, parent,
                            reinterpret_cast<HMENU>(kTabControlId), g_instance, nullptr);

    const wchar_t* titles[] = {L"Login", L"Serial", L"Clock", L"Integrity"};
    for (int i = 0; i < 4; ++i) {
        TCITEMW item{};
        item.mask = TCIF_TEXT;
        item.pszText = const_cast<LPWSTR>(titles[i]);
        TabCtrl_InsertItem(g_tab, i, &item);
    }

    g_panels[0] = create_panel(parent);
    g_panels[1] = create_panel(parent);
    g_panels[2] = create_panel(parent);
    g_panels[3] = create_panel(parent);

    create_login_panel(g_panels[0]);
    create_serial_panel(g_panels[1]);
    create_clock_panel(g_panels[2]);
    create_integrity_panel(g_panels[3]);

    show_panel(TabIndex::Login);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_COMMAND: {
            const int control = LOWORD(wparam);
            switch (control) {
                case kBtnLogin:
                    handle_login(hwnd);
                    break;
                case kBtnSerial:
                    handle_serial(hwnd);
                    break;
                case kBtnClock:
                    handle_clock(hwnd);
                    break;
                case kBtnIntegrity:
                    handle_integrity(hwnd);
                    break;
                default:
                    break;
            }
            break;
        }
        case WM_NOTIFY: {
            if (reinterpret_cast<LPNMHDR>(lparam)->idFrom == kTabControlId &&
                reinterpret_cast<LPNMHDR>(lparam)->code == TCN_SELCHANGE) {
                int selected = TabCtrl_GetCurSel(g_tab);
                show_panel(static_cast<TabIndex>(selected));
            }
            break;
        }
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
    return 0;
}

}  // namespace

void run_gui_login_demo() {
    g_instance = GetModuleHandleW(nullptr);
    INITCOMMONCONTROLSEX icc{sizeof(INITCOMMONCONTROLSEX), ICC_TAB_CLASSES};
    InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = L"ExLoaderTabDemo";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    g_main_window = CreateWindowExW(WS_EX_OVERLAPPEDWINDOW, wc.lpszClassName,
                                    L"ExLoader CrackMe Demo",
                                    WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME),
                                    CW_USEDEFAULT, CW_USEDEFAULT, 500, 330,
                                    nullptr, nullptr, g_instance, nullptr);
    if (!g_main_window) {
        MessageBoxW(nullptr, L"Failed to create CrackMe window", L"Error", MB_ICONERROR | MB_OK);
        return;
    }

    init_tabs(g_main_window);

    ShowWindow(g_main_window, SW_SHOWNORMAL);
    UpdateWindow(g_main_window);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

}  // namespace test_target
