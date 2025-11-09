#include "exloader/runtime/hooks/modules/proxy_hook/proxy_hook.hpp"

#if defined(_WIN32)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>

// Include winhttp.h first
#include <winhttp.h>

// Prevent wininet.h from redefining types already in winhttp.h
// by manually declaring what we need from wininet.h
#ifdef __cplusplus
extern "C" {
#endif

// We only need InternetSetOption from wininet.h
BOOL WINAPI InternetSetOptionA(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
BOOL WINAPI InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);

#ifdef UNICODE
#define InternetSetOption InternetSetOptionW
#else
#define InternetSetOption InternetSetOptionA
#endif

#ifdef __cplusplus
}
#endif

#include <minhook.h>

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

ProxyHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using InternetSetOptionFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
using WinHttpSetOptionFn = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);

InternetSetOptionFn g_internet_set_option = nullptr;
WinHttpSetOptionFn g_winhttp_set_option = nullptr;

void log_proxy_event(const char* api, DWORD option, const void* buffer, DWORD length) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", "network.proxy"},
        {"api", api},
        {"option", option}
    };
    if (buffer != nullptr && length > 0) {
        json["payload_hex"] = hex_encode(buffer, length, g_instance->context()->max_payload_bytes);
        json["payload_len"] = length;
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

BOOL WINAPI InternetSetOption_Hook(HINTERNET handle,
                                    DWORD option,
                                    LPVOID buffer,
                                    DWORD length) {
    BOOL result = g_internet_set_option(handle, option, buffer, length);
    log_proxy_event("InternetSetOption", option, buffer, length);
    return result;
}

BOOL WINAPI WinHttpSetOption_Hook(HINTERNET handle,
                                  DWORD option,
                                  LPVOID buffer,
                                  DWORD length) {
    BOOL result = g_winhttp_set_option(handle, option, buffer, length);
    log_proxy_event("WinHttpSetOption", option, buffer, length);
    return result;
}

bool hook_proxy_api(LPCWSTR module_name, LPCSTR proc_name, void* detour, void** original) {
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

bool ProxyHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void ProxyHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool ProxyHook::install_hooks() {
    return hook_proxy_api(L"wininet.dll", "InternetSetOptionW",
                          reinterpret_cast<void*>(&InternetSetOption_Hook),
                          reinterpret_cast<void**>(&g_internet_set_option)) &&
           hook_proxy_api(L"winhttp.dll", "WinHttpSetOption",
                          reinterpret_cast<void*>(&WinHttpSetOption_Hook),
                          reinterpret_cast<void**>(&g_winhttp_set_option));
}

void ProxyHook::uninstall_hooks() {
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

bool ProxyHook::initialize(const PluginContext&) {
    return false;
}

void ProxyHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
