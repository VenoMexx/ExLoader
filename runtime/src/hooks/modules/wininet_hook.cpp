#include "exloader/runtime/hooks/modules/wininet_hook.hpp"

#if defined(_WIN32)

#include <minhook.h>
#include <wininet.h>

#include <array>
#include <iterator>
#include <algorithm>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

WinInetHook* g_instance = nullptr;

using InternetConnectFn =
    HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
using HttpOpenRequestFn =
    HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR);
using HttpSendRequestFn =
    BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD);
using InternetOpenUrlFn =
    HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
using InternetOpenUrlAFn =
    HINTERNET(WINAPI*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
using InternetReadFileFn = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
using InternetCloseHandleFn = BOOL(WINAPI*)(HINTERNET);

InternetConnectFn g_orig_connect = nullptr;
HttpOpenRequestFn g_orig_open_request = nullptr;
HttpSendRequestFn g_orig_send_request = nullptr;
InternetOpenUrlFn g_orig_open_url_w = nullptr;
InternetOpenUrlAFn g_orig_open_url_a = nullptr;
InternetReadFileFn g_orig_read_file = nullptr;
InternetCloseHandleFn g_orig_close_handle = nullptr;

struct ConnectionInfo {
    std::string host;
    INTERNET_PORT port{};
};

struct InetRequestInfo {
    std::string host;
    INTERNET_PORT port{};
    std::string method;
    std::string path;
};

std::unordered_map<HINTERNET, ConnectionInfo> g_connections;
std::unordered_map<HINTERNET, InetRequestInfo> g_requests;
std::vector<void*> g_hook_targets;
std::mutex g_mutex;

std::string narrow(LPCWSTR wide) {
    if (wide == nullptr) {
        return {};
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, result.data(), len, nullptr, nullptr);
    return result;
}

std::string narrow(LPCWSTR wide, DWORD length) {
    if (wide == nullptr) {
        return {};
    }
    if (length == 0 || length == static_cast<DWORD>(-1)) {
        return narrow(wide);
    }
    int required = WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, static_cast<int>(length), result.data(), required, nullptr, nullptr);
    return result;
}

std::string narrow_ansi(LPCSTR ansi, DWORD length) {
    if (ansi == nullptr) {
        return {};
    }
    if (length == 0 || length == static_cast<DWORD>(-1)) {
        return std::string(ansi);
    }
    return std::string(ansi, ansi + length);
}

std::string ascii_preview(const void* data, std::size_t length, std::size_t max_chars = 1024) {
    if (data == nullptr || length == 0) {
        return {};
    }
    const auto* bytes = reinterpret_cast<const unsigned char*>(data);
    std::string preview;
    preview.reserve(std::min<std::size_t>(length, max_chars));
    const std::size_t limit = std::min<std::size_t>(length, max_chars);
    for (std::size_t i = 0; i < limit; ++i) {
        unsigned char ch = bytes[i];
        if (ch == '\r') {
            continue;
        }
        if (ch == '\n') {
            preview.push_back('\n');
        } else if (ch >= 32 && ch < 127) {
            preview.push_back(static_cast<char>(ch));
        } else {
            preview.push_back('.');
        }
    }
    if (length > limit) {
        preview.append("...");
    }
    return preview;
}

void log_event(const char* api,
               std::string_view type,
               const InetRequestInfo* info,
               const void* payload,
               std::size_t payload_len,
               const std::string* headers = nullptr) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    if (ctx == nullptr || ctx->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", type},
        {"api", api}
    };
    if (info != nullptr) {
        json["metadata"] = {
            {"host", info->host},
            {"port", info->port},
            {"method", info->method},
            {"path", info->path}
        };
    }
    if (payload != nullptr && payload_len > 0 && ctx != nullptr) {
        json["payload_hex"] =
            hex_encode(payload, payload_len, ctx->max_payload_bytes);
        json["payload_len"] = payload_len;
        if (info != nullptr) {
            json["payload_text"] = ascii_preview(payload, payload_len);
        }
    }
    if (headers != nullptr && !headers->empty()) {
        json["headers"] = *headers;
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    ctx->logger->log(std::move(json));
}

InetRequestInfo* find_request(HINTERNET handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_requests.find(handle);
    if (it == g_requests.end()) {
        return nullptr;
    }
    return &it->second;
}

InetRequestInfo parse_url(LPCWSTR url) {
    InetRequestInfo info{};
    if (url == nullptr) {
        return info;
    }
    URL_COMPONENTSW components{};
    wchar_t host[256]{};
    wchar_t path[1024]{};
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = static_cast<DWORD>(std::size(host));
    components.lpszUrlPath = path;
    components.dwUrlPathLength = static_cast<DWORD>(std::size(path));
    components.dwSchemeLength = 0;
    if (InternetCrackUrlW(url, 0, 0, &components)) {
        info.host = narrow(host);
        info.path = narrow(path);
        info.port = components.nPort;
    } else {
        info.path = narrow(url);
    }
    info.method = "GET";
    return info;
}

InetRequestInfo parse_url_ansi(LPCSTR url) {
    InetRequestInfo info{};
    if (url == nullptr) {
        return info;
    }
    URL_COMPONENTSA components{};
    char host[256]{};
    char path[1024]{};
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = static_cast<DWORD>(std::size(host));
    components.lpszUrlPath = path;
    components.dwUrlPathLength = static_cast<DWORD>(std::size(path));
    components.dwSchemeLength = 0;
    if (InternetCrackUrlA(url, 0, 0, &components)) {
        info.host = std::string(host);
        info.path = std::string(path);
        info.port = components.nPort;
    } else {
        info.path = std::string(url);
    }
    info.method = "GET";
    return info;
}

void erase_handle(HINTERNET handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_requests.erase(handle);
    g_connections.erase(handle);
}

HINTERNET WINAPI InternetConnect_Hook(HINTERNET hInternet,
                                      LPCWSTR server,
                                      INTERNET_PORT port,
                                      LPCWSTR user,
                                      LPCWSTR password,
                                      DWORD service,
                                      DWORD flags,
                                      DWORD_PTR context) {
    const HINTERNET result =
        g_orig_connect(hInternet, server, port, user, password, service, flags, context);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_connections[result] = {narrow(server), port};
    }
    return result;
}

HINTERNET WINAPI HttpOpenRequest_Hook(HINTERNET hConnect,
                                      LPCWSTR verb,
                                      LPCWSTR object_name,
                                      LPCWSTR version,
                                      LPCWSTR referrer,
                                      const LPCWSTR* accept,
                                      DWORD flags,
                                      DWORD_PTR context) {
    const HINTERNET result =
        g_orig_open_request(hConnect, verb, object_name, version, referrer,
                            const_cast<LPCWSTR*>(accept), flags, context);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto conn_it = g_connections.find(hConnect);
        InetRequestInfo info{};
        if (conn_it != g_connections.end()) {
            info.host = conn_it->second.host;
            info.port = conn_it->second.port;
        }
        info.method = narrow(verb);
        info.path = narrow(object_name);
        g_requests[result] = std::move(info);
    }
    return result;
}

BOOL WINAPI HttpSendRequest_Hook(HINTERNET hRequest,
                                 LPCWSTR headers,
                                 DWORD headers_length,
                                 LPVOID optional,
                                 DWORD optional_length) {
    InetRequestInfo* info = find_request(hRequest);
    std::string header_text = narrow(headers, headers_length);
    const std::string* header_ptr = header_text.empty() ? nullptr : &header_text;
    log_event("HttpSendRequest", "network.request", info, optional, optional_length, header_ptr);
    return g_orig_send_request(hRequest, headers, headers_length, optional, optional_length);
}

HINTERNET WINAPI InternetOpenUrl_Hook(HINTERNET hInternet,
                                      LPCWSTR url,
                                      LPCWSTR headers,
                                      DWORD headers_length,
                                      DWORD flags,
                                      DWORD_PTR context) {
    InetRequestInfo info = parse_url(url);
    std::string header_text = narrow(headers, headers_length);
    const std::string* header_ptr = header_text.empty() ? nullptr : &header_text;
    const HINTERNET result =
        g_orig_open_url_w(hInternet, url, headers, headers_length, flags, context);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_requests[result] = info;
        log_event("InternetOpenUrl", "network.request", &g_requests[result], nullptr, 0,
                  header_ptr);
    }
    return result;
}

HINTERNET WINAPI InternetOpenUrlA_Hook(HINTERNET hInternet,
                                       LPCSTR url,
                                       LPCSTR headers,
                                       DWORD headers_length,
                                       DWORD flags,
                                       DWORD_PTR context) {
    InetRequestInfo info = parse_url_ansi(url);
    std::string header_text = narrow_ansi(headers, headers_length);
    const std::string* header_ptr = header_text.empty() ? nullptr : &header_text;
    const HINTERNET result =
        g_orig_open_url_a(hInternet, url, headers, headers_length, flags, context);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_requests[result] = info;
        log_event("InternetOpenUrlA", "network.request", &g_requests[result], nullptr, 0,
                  header_ptr);
    }
    return result;
}

BOOL WINAPI InternetReadFile_Hook(HINTERNET hFile,
                                  LPVOID buffer,
                                  DWORD bytes_to_read,
                                  LPDWORD bytes_read) {
    const BOOL result = g_orig_read_file(hFile, buffer, bytes_to_read, bytes_read);
    if (result && bytes_read != nullptr && *bytes_read > 0) {
        InetRequestInfo* info = find_request(hFile);
        if (info != nullptr) {
            log_event("InternetReadFile", "network.response", info, buffer, *bytes_read);
        }
    }
    return result;
}

BOOL WINAPI InternetCloseHandle_Hook(HINTERNET handle) {
    erase_handle(handle);
    return g_orig_close_handle(handle);
}

bool hook_function(LPCSTR name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(L"wininet.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"wininet.dll");
    }
    if (module == nullptr) {
        return false;
    }
    FARPROC proc = GetProcAddress(module, name);
    if (proc == nullptr) {
        return false;
    }
    LPVOID target = reinterpret_cast<LPVOID>(proc);
    if (MH_CreateHook(target, detour, original) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        return false;
    }
    g_hook_targets.push_back(target);
    return true;
}

}  // namespace

bool WinInetHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ =
        hook_function("InternetConnectW", reinterpret_cast<void*>(&InternetConnect_Hook),
                      reinterpret_cast<void**>(&g_orig_connect)) &&
        hook_function("HttpOpenRequestW", reinterpret_cast<void*>(&HttpOpenRequest_Hook),
                      reinterpret_cast<void**>(&g_orig_open_request)) &&
        hook_function("HttpSendRequestW", reinterpret_cast<void*>(&HttpSendRequest_Hook),
                      reinterpret_cast<void**>(&g_orig_send_request)) &&
        hook_function("InternetOpenUrlW", reinterpret_cast<void*>(&InternetOpenUrl_Hook),
                      reinterpret_cast<void**>(&g_orig_open_url_w)) &&
        hook_function("InternetOpenUrlA", reinterpret_cast<void*>(&InternetOpenUrlA_Hook),
                      reinterpret_cast<void**>(&g_orig_open_url_a)) &&
        hook_function("InternetReadFile", reinterpret_cast<void*>(&InternetReadFile_Hook),
                      reinterpret_cast<void**>(&g_orig_read_file)) &&
        hook_function("InternetCloseHandle", reinterpret_cast<void*>(&InternetCloseHandle_Hook),
                      reinterpret_cast<void**>(&g_orig_close_handle));
    return hooks_installed_;
}

void WinInetHook::shutdown() {
    if (hooks_installed_) {
        for (void* target : g_hook_targets) {
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        g_hook_targets.clear();
        std::lock_guard<std::mutex> lock(g_mutex);
        g_requests.clear();
        g_connections.clear();
    }
    g_instance = nullptr;
    context_ = nullptr;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool WinInetHook::initialize(const PluginContext&) {
    return false;
}

void WinInetHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
