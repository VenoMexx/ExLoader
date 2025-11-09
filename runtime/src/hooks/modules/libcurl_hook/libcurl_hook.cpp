#include "exloader/runtime/hooks/modules/libcurl_hook/libcurl_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <minhook.h>

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

LibcurlHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;
std::unordered_map<void*, std::string> g_urls;
std::mutex g_mutex;

constexpr int CURLOPT_URL = 10002;

using CurlEasySetoptFn = int(__cdecl*)(void*, int, ...);
using CurlEasyPerformFn = int(__cdecl*)(void*);

CurlEasySetoptFn g_curl_setopt = nullptr;
CurlEasyPerformFn g_curl_perform = nullptr;

void log_curl_event(const char* api, void* handle, int result) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", "network.libcurl"},
        {"api", api},
        {"result", result}
    };

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_urls.find(handle);
        if (it != g_urls.end()) {
            json["url"] = it->second;
        }
    }

    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

int __cdecl CurlEasySetopt_Hook(void* handle, int option, ... ) {
    va_list args;
    va_start(args, option);
    int result = g_curl_setopt(handle, option, args);
    if (option == CURLOPT_URL) {
        const char* url = va_arg(args, const char*);
        std::lock_guard<std::mutex> lock(g_mutex);
        g_urls[handle] = url ? url : "";
    }
    va_end(args);
    return result;
}

int __cdecl CurlEasyPerform_Hook(void* handle) {
    int result = g_curl_perform(handle);
    log_curl_event("curl_easy_perform", handle, result);
    return result;
}

bool hook_libcurl_api(LPCWSTR module_name, LPCSTR proc_name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(module_name);
    if (module == nullptr) {
        module = LoadLibraryW(module_name);
    }
    if (module == nullptr) {
        return false;
    }

    FARPROC proc = GetProcAddress(module, proc_name);
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

bool LibcurlHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void LibcurlHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_urls.clear();
}

bool LibcurlHook::install_hooks() {
    return hook_libcurl_api(L"libcurl.dll", "curl_easy_setopt",
                            reinterpret_cast<void*>(&CurlEasySetopt_Hook),
                            reinterpret_cast<void**>(&g_curl_setopt)) &&
           hook_libcurl_api(L"libcurl.dll", "curl_easy_perform",
                            reinterpret_cast<void*>(&CurlEasyPerform_Hook),
                            reinterpret_cast<void**>(&g_curl_perform));
}

void LibcurlHook::uninstall_hooks() {
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

bool LibcurlHook::initialize(const PluginContext&) {
    return false;
}

void LibcurlHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif  // _WIN32
