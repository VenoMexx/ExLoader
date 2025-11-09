#include "exloader/runtime/hooks/modules/winsock_hook.hpp"

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>
#include <minhook.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <limits>
#include <system_error>
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

struct HttpMetadata {
    bool valid{false};
    bool is_request{true};
    std::string method;
    std::string path;
    std::string version;
    int status{-1};
    std::string reason;
    std::string host;
};

constexpr std::array<std::string_view, 8> kHttpMethods = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"
};

std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string_view find_header_value(std::string_view headers, std::string_view key) {
    std::size_t pos = 0;
    while (pos < headers.size()) {
        std::size_t end = headers.find("\r\n", pos);
        if (end == std::string_view::npos) {
            end = headers.size();
        }
        std::string_view line = headers.substr(pos, end - pos);
        if (line.empty()) {
            break;
        }
        const std::size_t colon = line.find(':');
        if (colon != std::string_view::npos) {
            if (iequals(line.substr(0, colon), key)) {
                return trim(line.substr(colon + 1));
            }
        }
        pos = end + 2;
    }
    return {};
}

bool parse_http_metadata(const std::uint8_t* data, std::size_t length, HttpMetadata& meta) {
    if (data == nullptr || length < 4) {
        return false;
    }
    constexpr std::size_t kMaxInspect = 4096;
    const std::size_t inspect_len = std::min<std::size_t>(length, kMaxInspect);
    std::string_view view(reinterpret_cast<const char*>(data), inspect_len);
    std::size_t first_eol = view.find("\n");
    if (first_eol == std::string_view::npos) {
        return false;
    }
    std::string_view first_line = view.substr(0, first_eol);
    if (!first_line.empty() && first_line.back() == '\r') {
        first_line.remove_suffix(1);
    }
    if (first_line.empty()) {
        return false;
    }

    HttpMetadata result{};
    if (first_line.size() > 5 && first_line.rfind("HTTP/", 0) == 0) {
        result.is_request = false;
        const std::size_t space_pos = first_line.find(' ');
        if (space_pos == std::string_view::npos) {
            return false;
        }
        result.version = std::string(first_line.substr(5, space_pos - 5));
        std::string_view remainder = trim(first_line.substr(space_pos + 1));
        const std::size_t status_end = remainder.find(' ');
        std::string_view status_str = remainder.substr(0, status_end);
        int parsed_status = 0;
        const auto conv = std::from_chars(status_str.data(),
                                          status_str.data() + status_str.size(), parsed_status);
        if (conv.ec == std::errc()) {
            result.status = parsed_status;
        }
        if (status_end != std::string_view::npos) {
            result.reason = std::string(trim(remainder.substr(status_end + 1)));
        }
    } else {
        bool method_found = false;
        for (std::string_view method : kHttpMethods) {
            if (first_line.size() > method.size() + 1 &&
                first_line.rfind(method, 0) == 0 &&
                first_line[method.size()] == ' ') {
                result.is_request = true;
                result.method = std::string(method);
                const std::size_t second_space =
                    first_line.find(' ', method.size() + 1);
                if (second_space == std::string_view::npos) {
                    return false;
                }
                result.path = std::string(first_line.substr(method.size() + 1,
                                                            second_space - method.size() - 1));
                result.version = std::string(first_line.substr(second_space + 1));
                method_found = true;
                break;
            }
        }
        if (!method_found) {
            return false;
        }
    }

    std::string_view host_value =
        find_header_value(view, "host");
    if (!host_value.empty()) {
        result.host = std::string(host_value);
    }
    result.valid = true;
    meta = std::move(result);
    return true;
}

void attach_http_metadata(nlohmann::json& json, const HttpMetadata& meta) {
    if (!meta.valid) {
        return;
    }
    nlohmann::json http;
    http["direction"] = meta.is_request ? "request" : "response";
    if (!meta.version.empty()) {
        http["version"] = meta.version;
    }
    if (meta.is_request) {
        if (!meta.method.empty()) {
            http["method"] = meta.method;
        }
        if (!meta.path.empty()) {
            http["path"] = meta.path;
        }
    } else {
        if (meta.status >= 0) {
            http["status"] = meta.status;
        }
        if (!meta.reason.empty()) {
            http["reason"] = meta.reason;
        }
    }
    if (!meta.host.empty()) {
        http["host"] = meta.host;
    }
    json["http"] = std::move(http);
}

void annotate_protocol_hint(nlohmann::json& json, const std::uint8_t* data, std::size_t length) {
    if (data == nullptr || length < 2) {
        return;
    }
    if (data[0] == 0xA0 || data[0] == 0xA1) {
        json["protocol_hint"] = "farmex-binary";
        json["protocol_hint_mode"] = data[0] == 0xA0 ? "request" : "response";
    }
}

std::string ascii_preview(const std::uint8_t* data, std::size_t length, std::size_t max_chars = 1024) {
    if (data == nullptr || length == 0) {
        return {};
    }
    std::string preview;
    preview.reserve(std::min<std::size_t>(length, max_chars));
    const std::size_t limit = std::min<std::size_t>(length, max_chars);
    for (std::size_t i = 0; i < limit; ++i) {
        unsigned char ch = data[i];
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

WinSockHook* g_instance = nullptr;

using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
using RecvFn = int (WSAAPI*)(SOCKET, char*, int, int);
using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using RecvFromFn = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
using WSASendFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSASendToFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int,
                                   LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using WSARecvFromFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, sockaddr*, LPINT,
                                     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using CloseSocketFn = int (WSAAPI*)(SOCKET);

ConnectFn g_orig_connect = nullptr;
SendFn g_orig_send = nullptr;
RecvFn g_orig_recv = nullptr;
SendToFn g_orig_sendto = nullptr;
RecvFromFn g_orig_recvfrom = nullptr;
WSASendFn g_orig_wsa_send = nullptr;
WSARecvFn g_orig_wsa_recv = nullptr;
WSASendToFn g_orig_wsa_sendto = nullptr;
WSARecvFromFn g_orig_wsa_recvfrom = nullptr;
CloseSocketFn g_orig_close = nullptr;

std::unordered_map<SOCKET, std::string> g_endpoints;
std::mutex g_mutex;
std::vector<void*> g_hook_targets;

std::string describe_endpoint(const sockaddr* addr, int len) {
    char host[INET6_ADDRSTRLEN] = {};
    std::string result;
    if (addr->sa_family == AF_INET) {
        auto* ipv4 = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host));
        result = host;
        result += ':';
        result += std::to_string(ntohs(ipv4->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(addr);
        inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host));
        result = '[';
        result += host;
        result += "]:";
        result += std::to_string(ntohs(ipv6->sin6_port));
    } else {
        result = "unknown";
    }
    (void)len;
    return result;
}

void log_event(const char* api,
               std::string_view type,
               SOCKET s,
               const void* payload,
               std::size_t length) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    if (ctx == nullptr || ctx->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", type},
        {"api", api},
        {"socket", s},
    };
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_endpoints.find(s);
        if (it != g_endpoints.end()) {
            json["endpoint"] = it->second;
        }
    }
    if (payload != nullptr && length > 0) {
        json["payload_hex"] =
            hex_encode(payload, length, ctx->max_payload_bytes);
        json["payload_len"] = length;
        HttpMetadata meta;
        if (parse_http_metadata(reinterpret_cast<const std::uint8_t*>(payload), length, meta)) {
            attach_http_metadata(json, meta);
            json["payload_text"] =
                ascii_preview(reinterpret_cast<const std::uint8_t*>(payload), length);
        }
        annotate_protocol_hint(json, reinterpret_cast<const std::uint8_t*>(payload), length);
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    ctx->logger->log(std::move(json));
}

struct WsabufSnapshot {
    std::vector<std::uint8_t> prefix;
    std::size_t total_length{0};
};

WsabufSnapshot snapshot_wsabuf(const WSABUF* buffers,
                               DWORD buffer_count,
                               std::size_t max_bytes,
                               std::size_t clamp_length = std::numeric_limits<std::size_t>::max()) {
    WsabufSnapshot snapshot;
    if (buffers == nullptr || buffer_count == 0 || max_bytes == 0) {
        return snapshot;
    }
    snapshot.prefix.reserve(std::min<std::size_t>(max_bytes, 1024));
    std::size_t remaining_copy = max_bytes;
    std::size_t remaining_clamp = clamp_length;
    bool clamp_active = clamp_length != std::numeric_limits<std::size_t>::max();
    for (DWORD i = 0; i < buffer_count && remaining_copy > 0; ++i) {
        const WSABUF& wsabuf = buffers[i];
        if (wsabuf.buf == nullptr || wsabuf.len == 0) {
            continue;
        }
        std::size_t chunk_len = wsabuf.len;
        if (clamp_active) {
            if (remaining_clamp == 0) {
                break;
            }
            if (chunk_len > remaining_clamp) {
                chunk_len = remaining_clamp;
            }
            remaining_clamp -= chunk_len;
        }
        snapshot.total_length += chunk_len;
        std::size_t to_copy = std::min<std::size_t>(chunk_len, remaining_copy);
        if (to_copy > 0) {
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(wsabuf.buf);
            snapshot.prefix.insert(snapshot.prefix.end(), bytes, bytes + to_copy);
            remaining_copy -= to_copy;
        }
    }
    return snapshot;
}

void log_wsabuf_event(const char* api,
                      std::string_view type,
                      SOCKET s,
                      const WsabufSnapshot& snapshot,
                      DWORD buffer_count,
                      DWORD flags,
                      bool overlapped,
                      std::size_t reported_len) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    if (ctx == nullptr || ctx->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", type},
        {"api", api},
        {"socket", s},
        {"buffer_count", buffer_count},
        {"flags", flags},
        {"overlapped", overlapped}
    };
    if (reported_len > 0) {
        json["payload_len"] = reported_len;
    } else if (snapshot.total_length > 0) {
        json["payload_len"] = snapshot.total_length;
    }
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_endpoints.find(s);
        if (it != g_endpoints.end()) {
            json["endpoint"] = it->second;
        }
    }
    if (!snapshot.prefix.empty()) {
        json["payload_hex"] =
            hex_encode(snapshot.prefix.data(), snapshot.prefix.size(), ctx->max_payload_bytes);
        HttpMetadata meta;
        if (parse_http_metadata(snapshot.prefix.data(), snapshot.prefix.size(), meta)) {
            attach_http_metadata(json, meta);
            json["payload_text"] = ascii_preview(snapshot.prefix.data(), snapshot.prefix.size());
        }
        annotate_protocol_hint(json, snapshot.prefix.data(), snapshot.prefix.size());
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    ctx->logger->log(std::move(json));
}

int WSAAPI connect_hook(SOCKET s, const sockaddr* addr, int len) {
    const int result = g_orig_connect(s, addr, len);
    if (result == 0) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_endpoints[s] = describe_endpoint(addr, len);
    }
    return result;
}

int WSAAPI send_hook(SOCKET s, const char* buf, int len, int flags) {
    if (len > 0) {
        log_event("send", "network.request", s, buf, len);
    }
    return g_orig_send(s, buf, len, flags);
}

int WSAAPI recv_hook(SOCKET s, char* buf, int len, int flags) {
    const int ret = g_orig_recv(s, buf, len, flags);
    if (ret > 0) {
        log_event("recv", "network.response", s, buf, ret);
    }
    return ret;
}

int WSAAPI sendto_hook(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen) {
    if (to != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_endpoints[s] = describe_endpoint(to, tolen);
    }
    if (len > 0) {
        log_event("sendto", "network.request", s, buf, len);
    }
    return g_orig_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI recvfrom_hook(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen) {
    const int ret = g_orig_recvfrom(s, buf, len, flags, from, fromlen);
    if (ret > 0) {
        if (from != nullptr && fromlen != nullptr && *fromlen > 0) {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_endpoints[s] = describe_endpoint(from, *fromlen);
        }
        log_event("recvfrom", "network.response", s, buf, ret);
    }
    return ret;
}

int WSAAPI wsa_send_hook(SOCKET s,
                         LPWSABUF buffers,
                         DWORD buffer_count,
                         LPDWORD bytes_sent,
                         DWORD flags,
                         LPWSAOVERLAPPED overlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    WsabufSnapshot snapshot;
    if (ctx != nullptr) {
        snapshot = snapshot_wsabuf(buffers, buffer_count, ctx->max_payload_bytes);
    }
    const int result =
        g_orig_wsa_send(s, buffers, buffer_count, bytes_sent, flags, overlapped, completion);
    if (ctx != nullptr) {
        DWORD reported = (result == 0 && bytes_sent != nullptr) ? *bytes_sent : 0;
        log_wsabuf_event("WSASend", "network.request", s, snapshot, buffer_count, flags,
                         overlapped != nullptr, reported);
    }
    return result;
}

int WSAAPI wsa_recv_hook(SOCKET s,
                         LPWSABUF buffers,
                         DWORD buffer_count,
                         LPDWORD bytes_received,
                         LPDWORD flags_ptr,
                         LPWSAOVERLAPPED overlapped,
                         LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    const int result =
        g_orig_wsa_recv(s, buffers, buffer_count, bytes_received, flags_ptr, overlapped, completion);
    if (ctx != nullptr && result == 0 && bytes_received != nullptr && *bytes_received > 0) {
        WsabufSnapshot snapshot = snapshot_wsabuf(
            buffers, buffer_count, ctx->max_payload_bytes, *bytes_received);
        log_wsabuf_event("WSARecv", "network.response", s, snapshot, buffer_count,
                         flags_ptr ? *flags_ptr : 0, overlapped != nullptr, *bytes_received);
    }
    return result;
}

int WSAAPI wsa_sendto_hook(SOCKET s,
                           LPWSABUF buffers,
                           DWORD buffer_count,
                           LPDWORD bytes_sent,
                           DWORD flags,
                           const sockaddr* to,
                           int tolen,
                           LPWSAOVERLAPPED overlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    if (to != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_endpoints[s] = describe_endpoint(to, tolen);
    }
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    WsabufSnapshot snapshot;
    if (ctx != nullptr) {
        snapshot = snapshot_wsabuf(buffers, buffer_count, ctx->max_payload_bytes);
    }
    const int result = g_orig_wsa_sendto(
        s, buffers, buffer_count, bytes_sent, flags, to, tolen, overlapped, completion);
    if (ctx != nullptr) {
        DWORD reported = (result == 0 && bytes_sent != nullptr) ? *bytes_sent : 0;
        log_wsabuf_event("WSASendTo", "network.request", s, snapshot, buffer_count, flags,
                         overlapped != nullptr, reported);
    }
    return result;
}

int WSAAPI wsa_recvfrom_hook(SOCKET s,
                             LPWSABUF buffers,
                             DWORD buffer_count,
                             LPDWORD bytes_received,
                             LPDWORD flags_ptr,
                             sockaddr* from,
                             LPINT fromlen,
                             LPWSAOVERLAPPED overlapped,
                             LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    const int result = g_orig_wsa_recvfrom(
        s, buffers, buffer_count, bytes_received, flags_ptr, from, fromlen, overlapped, completion);
    if (result == 0 && from != nullptr && fromlen != nullptr && *fromlen > 0) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_endpoints[s] = describe_endpoint(from, *fromlen);
    }
    if (ctx != nullptr && result == 0 && bytes_received != nullptr && *bytes_received > 0) {
        WsabufSnapshot snapshot = snapshot_wsabuf(
            buffers, buffer_count, ctx->max_payload_bytes, *bytes_received);
        log_wsabuf_event("WSARecvFrom", "network.response", s, snapshot, buffer_count,
                         flags_ptr ? *flags_ptr : 0, overlapped != nullptr, *bytes_received);
    }
    return result;
}

int WSAAPI closesocket_hook(SOCKET s) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_endpoints.erase(s);
    return g_orig_close(s);
}

bool hook_function(LPCSTR name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(L"ws2_32.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"ws2_32.dll");
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

bool WinSockHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    bool ok = true;
    ok &= hook_function("connect", reinterpret_cast<void*>(&connect_hook),
                        reinterpret_cast<void**>(&g_orig_connect));
    ok &= hook_function("send", reinterpret_cast<void*>(&send_hook),
                        reinterpret_cast<void**>(&g_orig_send));
    ok &= hook_function("recv", reinterpret_cast<void*>(&recv_hook),
                        reinterpret_cast<void**>(&g_orig_recv));
    ok &= hook_function("sendto", reinterpret_cast<void*>(&sendto_hook),
                        reinterpret_cast<void**>(&g_orig_sendto));
    ok &= hook_function("recvfrom", reinterpret_cast<void*>(&recvfrom_hook),
                        reinterpret_cast<void**>(&g_orig_recvfrom));
    ok &= hook_function("WSASend", reinterpret_cast<void*>(&wsa_send_hook),
                        reinterpret_cast<void**>(&g_orig_wsa_send));
    ok &= hook_function("WSARecv", reinterpret_cast<void*>(&wsa_recv_hook),
                        reinterpret_cast<void**>(&g_orig_wsa_recv));
    ok &= hook_function("WSASendTo", reinterpret_cast<void*>(&wsa_sendto_hook),
                        reinterpret_cast<void**>(&g_orig_wsa_sendto));
    ok &= hook_function("WSARecvFrom", reinterpret_cast<void*>(&wsa_recvfrom_hook),
                        reinterpret_cast<void**>(&g_orig_wsa_recvfrom));
    ok &= hook_function("closesocket", reinterpret_cast<void*>(&closesocket_hook),
                        reinterpret_cast<void**>(&g_orig_close));
    hooks_installed_ = ok;
    return hooks_installed_;
}

void WinSockHook::shutdown() {
    if (hooks_installed_) {
        for (void* target : g_hook_targets) {
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        g_hook_targets.clear();
        std::lock_guard<std::mutex> lock(g_mutex);
        g_endpoints.clear();
    }
    g_instance = nullptr;
    context_ = nullptr;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool WinSockHook::initialize(const PluginContext&) {
    return false;
}

void WinSockHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
