#include "exloader/runtime/hooks/modules/winhttp_hook.hpp"

#if defined(_WIN32)

#include <minhook.h>
#include <winhttp.h>

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

WinHttpHook* g_instance = nullptr;

using WinHttpConnectFn = HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
using WinHttpOpenRequestFn =
    HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
using WinHttpSendRequestFn =
    BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD_PTR, DWORD_PTR);
using WinHttpReceiveResponseFn = BOOL(WINAPI*)(HINTERNET, LPVOID);
using WinHttpReadDataFn = BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD);
using WinHttpCloseHandleFn = BOOL(WINAPI*)(HINTERNET);

WinHttpConnectFn g_orig_connect = nullptr;
WinHttpOpenRequestFn g_orig_open_request = nullptr;
WinHttpSendRequestFn g_orig_send_request = nullptr;
WinHttpReceiveResponseFn g_orig_receive_response = nullptr;
WinHttpReadDataFn g_orig_read_data = nullptr;
WinHttpCloseHandleFn g_orig_close_handle = nullptr;

struct ConnectInfo {
    std::string host;
    INTERNET_PORT port{};
};

struct RequestInfo {
    std::string host;
    INTERNET_PORT port{};
    std::string method;
    std::string path;
};

std::unordered_map<HINTERNET, ConnectInfo> g_connects;
std::unordered_map<HINTERNET, RequestInfo> g_requests;
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

void log_event(const char* api,
               std::string_view type,
               const RequestInfo* request,
               const void* payload,
               std::size_t payload_len) {
    const PluginContext* ctx = g_instance ? g_instance->context() : nullptr;
    if (ctx == nullptr || ctx->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", type},
        {"api", api},
    };
    if (request != nullptr) {
        json["metadata"] = {
            {"host", request->host},
            {"port", request->port},
            {"method", request->method},
            {"path", request->path}
        };
    }

    if (payload != nullptr && payload_len > 0 && ctx != nullptr) {
        json["payload_hex"] =
            hex_encode(payload, payload_len, ctx->max_payload_bytes);
        json["payload_len"] = payload_len;
    }

    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    ctx->logger->log(std::move(json));
}

RequestInfo* get_request_info(HINTERNET handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_requests.find(handle);
    if (it == g_requests.end()) {
        return nullptr;
    }
    return &it->second;
}

void remove_handle(HINTERNET handle) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_requests.erase(handle);
    g_connects.erase(handle);
}

HINTERNET WINAPI WinHttpConnect_Hook(HINTERNET hSession,
                                     LPCWSTR server,
                                     INTERNET_PORT port,
                                     DWORD reserved) {
    const HINTERNET result = g_orig_connect(hSession, server, port, reserved);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_connects[result] = {narrow(server), port};
    }
    return result;
}

HINTERNET WINAPI WinHttpOpenRequest_Hook(HINTERNET hConnect,
                                         LPCWSTR verb,
                                         LPCWSTR object_name,
                                         LPCWSTR version,
                                         LPCWSTR referrer,
                                         const LPCWSTR* accept_types,
                                         DWORD flags) {
    const HINTERNET result =
        g_orig_open_request(hConnect, verb, object_name, version, referrer,
                            const_cast<LPCWSTR*>(accept_types), flags);
    if (result != nullptr) {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto connect_it = g_connects.find(hConnect);
        RequestInfo info{};
        if (connect_it != g_connects.end()) {
            info.host = connect_it->second.host;
            info.port = connect_it->second.port;
        }
        info.method = narrow(verb);
        info.path = narrow(object_name);
        g_requests[result] = std::move(info);
    }
    return result;
}

BOOL WINAPI WinHttpSendRequest_Hook(HINTERNET hRequest,
                                    LPCWSTR headers,
                                    DWORD headers_length,
                                    LPVOID optional,
                                    DWORD optional_length,
                                    DWORD_PTR total_length,
                                    DWORD_PTR context) {
    RequestInfo* info = get_request_info(hRequest);
    if (info != nullptr) {
        log_event("WinHttpSendRequest", "network.request", info, optional,
                  optional_length);
    }
    return g_orig_send_request(hRequest, headers, headers_length, optional, optional_length,
                               total_length, context);
}

BOOL WINAPI WinHttpReceiveResponse_Hook(HINTERNET hRequest, LPVOID reserved) {
    const BOOL result = g_orig_receive_response(hRequest, reserved);
    if (result) {
        RequestInfo* info = get_request_info(hRequest);
        if (info != nullptr) {
            log_event("WinHttpReceiveResponse", "network.response", info, nullptr, 0);
        }
    }
    return result;
}

BOOL WINAPI WinHttpReadData_Hook(HINTERNET hRequest,
                                 LPVOID buffer,
                                 DWORD bytes_to_read,
                                 LPDWORD bytes_read) {
    const BOOL result = g_orig_read_data(hRequest, buffer, bytes_to_read, bytes_read);
    if (result && bytes_read != nullptr && *bytes_read > 0) {
        RequestInfo* info = get_request_info(hRequest);
        if (info != nullptr) {
            log_event("WinHttpReadData", "network.response", info, buffer, *bytes_read);
        }
    }
    return result;
}

BOOL WINAPI WinHttpCloseHandle_Hook(HINTERNET handle) {
    remove_handle(handle);
    return g_orig_close_handle(handle);
}

bool install_hook(LPCSTR name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(L"winhttp.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"winhttp.dll");
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

bool WinHttpHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void WinHttpHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool WinHttpHook::install_hooks() {
    const bool ok = install_hook("WinHttpConnect", reinterpret_cast<void*>(&WinHttpConnect_Hook),
                                 reinterpret_cast<void**>(&g_orig_connect)) &&
                    install_hook("WinHttpOpenRequest",
                                 reinterpret_cast<void*>(&WinHttpOpenRequest_Hook),
                                 reinterpret_cast<void**>(&g_orig_open_request)) &&
                    install_hook("WinHttpSendRequest",
                                 reinterpret_cast<void*>(&WinHttpSendRequest_Hook),
                                 reinterpret_cast<void**>(&g_orig_send_request)) &&
                    install_hook("WinHttpReceiveResponse",
                                 reinterpret_cast<void*>(&WinHttpReceiveResponse_Hook),
                                 reinterpret_cast<void**>(&g_orig_receive_response)) &&
                    install_hook("WinHttpReadData", reinterpret_cast<void*>(&WinHttpReadData_Hook),
                                 reinterpret_cast<void**>(&g_orig_read_data)) &&
                    install_hook("WinHttpCloseHandle",
                                 reinterpret_cast<void*>(&WinHttpCloseHandle_Hook),
                                 reinterpret_cast<void**>(&g_orig_close_handle));
    return ok;
}

void WinHttpHook::uninstall_hooks() {
    if (!hooks_installed_) {
        return;
    }
    for (void* target : g_hook_targets) {
        MH_DisableHook(target);
        MH_RemoveHook(target);
    }
    g_hook_targets.clear();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_requests.clear();
        g_connects.clear();
    }
    hooks_installed_ = false;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool WinHttpHook::initialize(const PluginContext&) {
    return false;
}

void WinHttpHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
