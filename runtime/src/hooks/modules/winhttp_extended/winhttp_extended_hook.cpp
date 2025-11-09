#include "exloader/runtime/hooks/modules/winhttp_extended/winhttp_extended_hook.hpp"

#if defined(_WIN32)

#include <minhook.h>
#include <winhttp.h>

#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

WinHttpExtendedHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;
std::mutex g_mutex;

using WinHttpQueryHeadersFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
using WinHttpQueryDataAvailableFn = BOOL(WINAPI*)(HINTERNET, LPDWORD);
using WinHttpWriteDataFn = BOOL(WINAPI*)(HINTERNET, LPCVOID, DWORD, LPDWORD);

WinHttpQueryHeadersFn g_query_headers = nullptr;
WinHttpQueryDataAvailableFn g_query_data = nullptr;
WinHttpWriteDataFn g_write_data = nullptr;

void log_extended_event(const char* api, const void* payload, std::size_t length) {
    if (g_instance == nullptr || g_instance->context() == nullptr ||
        g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", "network.winhttp.extended"},
        {"api", api}
    };
    if (payload != nullptr && length > 0) {
        json["payload_hex"] = hex_encode(payload, length, g_instance->context()->max_payload_bytes);
        json["payload_len"] = length;
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

BOOL WINAPI WinHttpQueryHeaders_Hook(HINTERNET hRequest,
                                     DWORD info_level,
                                     LPCWSTR name,
                                     LPVOID buffer,
                                     LPDWORD buffer_length,
                                     LPDWORD index) {
    BOOL result = g_query_headers(hRequest, info_level, name, buffer, buffer_length, index);
    if (result && buffer != nullptr && buffer_length != nullptr) {
        log_extended_event("WinHttpQueryHeaders", buffer, *buffer_length);
    }
    return result;
}

BOOL WINAPI WinHttpQueryDataAvailable_Hook(HINTERNET hRequest, LPDWORD bytes_available) {
    BOOL result = g_query_data(hRequest, bytes_available);
    if (result && bytes_available != nullptr) {
        log_extended_event("WinHttpQueryDataAvailable", bytes_available, sizeof(DWORD));
    }
    return result;
}

BOOL WINAPI WinHttpWriteData_Hook(HINTERNET hRequest,
                                  LPCVOID buffer,
                                  DWORD bytes_to_write,
                                  LPDWORD bytes_written) {
    BOOL result = g_write_data(hRequest, buffer, bytes_to_write, bytes_written);
    if (result && buffer != nullptr && bytes_to_write > 0) {
        log_extended_event("WinHttpWriteData", buffer, bytes_to_write);
    }
    return result;
}

bool hook_api(LPCSTR name, void* detour, void** original) {
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

bool WinHttpExtendedHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void WinHttpExtendedHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool WinHttpExtendedHook::install_hooks() {
    return hook_api("WinHttpQueryHeaders", reinterpret_cast<void*>(&WinHttpQueryHeaders_Hook),
                    reinterpret_cast<void**>(&g_query_headers)) &&
           hook_api("WinHttpQueryDataAvailable", reinterpret_cast<void*>(&WinHttpQueryDataAvailable_Hook),
                    reinterpret_cast<void**>(&g_query_data)) &&
           hook_api("WinHttpWriteData", reinterpret_cast<void*>(&WinHttpWriteData_Hook),
                    reinterpret_cast<void**>(&g_write_data));
}

void WinHttpExtendedHook::uninstall_hooks() {
    if (!hooks_installed_) {
        return;
    }
    for (void* target : g_hook_targets) {
        MH_DisableHook(target);
        MH_RemoveHook(target);
    }
    g_hook_targets.clear();
    hooks_installed_ = false;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool WinHttpExtendedHook::initialize(const PluginContext&) {
    return false;
}

void WinHttpExtendedHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
