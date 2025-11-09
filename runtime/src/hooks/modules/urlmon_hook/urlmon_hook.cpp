#include "exloader/runtime/hooks/modules/urlmon_hook/urlmon_hook.hpp"

#if defined(_WIN32)

#include <minhook.h>
#include <urlmon.h>

#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

UrlmonHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using URLDownloadToFileFn = HRESULT(WINAPI*)(LPUNKNOWN, LPCWSTR, LPCWSTR, DWORD, LPBINDSTATUSCALLBACK);
using URLOpenBlockingStreamFn = HRESULT(WINAPI*)(LPUNKNOWN, LPCWSTR, LPSTREAM*, DWORD, LPBINDSTATUSCALLBACK);
using URLOpenStreamFn = HRESULT(WINAPI*)(LPUNKNOWN, LPCWSTR, DWORD, LPBINDSTATUSCALLBACK);

URLDownloadToFileFn g_url_download = nullptr;
URLOpenBlockingStreamFn g_url_open_blocking = nullptr;
URLOpenStreamFn g_url_open_stream = nullptr;

std::string narrow(LPCWSTR text) {
    if (!text) {
        return {};
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), len, nullptr, nullptr);
    return result;
}

void log_url_event(const char* api,
                   std::string_view url,
                   HRESULT hr,
                   std::string_view extra = {}) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", "network.urlmon"},
        {"api", api},
        {"url", url},
        {"hr", hr}
    };
    if (!extra.empty()) {
        json["extra"] = extra;
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

HRESULT WINAPI URLDownloadToFile_Hook(LPUNKNOWN caller,
                                      LPCWSTR url,
                                      LPCWSTR file_name,
                                      DWORD reserved,
                                      LPBINDSTATUSCALLBACK callback) {
    const HRESULT hr = g_url_download(caller, url, file_name, reserved, callback);
    log_url_event("URLDownloadToFileW", narrow(url), hr, narrow(file_name));
    return hr;
}

HRESULT WINAPI URLOpenBlockingStream_Hook(LPUNKNOWN caller,
                                          LPCWSTR url,
                                          LPSTREAM* stream,
                                          DWORD reserved,
                                          LPBINDSTATUSCALLBACK callback) {
    const HRESULT hr = g_url_open_blocking(caller, url, stream, reserved, callback);
    log_url_event("URLOpenBlockingStreamW", narrow(url), hr);
    return hr;
}

HRESULT WINAPI URLOpenStream_Hook(LPUNKNOWN caller,
                                  LPCWSTR url,
                                  DWORD reserved,
                                  LPBINDSTATUSCALLBACK callback) {
    const HRESULT hr = g_url_open_stream(caller, url, reserved, callback);
    log_url_event("URLOpenStreamW", narrow(url), hr);
    return hr;
}

bool hook_function(LPCWSTR module_name, LPCSTR proc_name, void* detour, void** original) {
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

bool UrlmonHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void UrlmonHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool UrlmonHook::install_hooks() {
    return hook_function(L"urlmon.dll", "URLDownloadToFileW",
                         reinterpret_cast<void*>(&URLDownloadToFile_Hook),
                         reinterpret_cast<void**>(&g_url_download)) &&
           hook_function(L"urlmon.dll", "URLOpenBlockingStreamW",
                         reinterpret_cast<void*>(&URLOpenBlockingStream_Hook),
                         reinterpret_cast<void**>(&g_url_open_blocking)) &&
           hook_function(L"urlmon.dll", "URLOpenStreamW",
                         reinterpret_cast<void*>(&URLOpenStream_Hook),
                         reinterpret_cast<void**>(&g_url_open_stream));
}

void UrlmonHook::uninstall_hooks() {
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

bool UrlmonHook::initialize(const PluginContext&) {
    return false;
}

void UrlmonHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
