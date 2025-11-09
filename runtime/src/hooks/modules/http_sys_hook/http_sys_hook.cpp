#include "exloader/runtime/hooks/modules/http_sys_hook/http_sys_hook.hpp"

#if defined(_WIN32)

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <http.h>
#include <minhook.h>

#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

#pragma comment(lib, "httpapi.lib")

namespace exloader::runtime::hooks::modules {

namespace {

HttpSysHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using HttpSendHttpResponseFn = ULONG(WINAPI*)(HANDLE, HTTP_REQUEST_ID, ULONG, PHTTP_RESPONSE, PVOID, PULONG, PVOID, ULONG, PHTTP_LOG_FIELDS_DATA, PVOID);
using HttpSendResponseEntityBodyFn = ULONG(WINAPI*)(HANDLE, HTTP_REQUEST_ID, ULONG, USHORT, PHTTP_DATA_CHUNK, PULONG, PVOID, ULONG, PHTTP_LOG_FIELDS_DATA, PVOID);

HttpSendHttpResponseFn g_send_response = nullptr;
HttpSendResponseEntityBodyFn g_send_entity = nullptr;

void log_http_event(const char* api, ULONG status, ULONG bytes) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", "network.http_sys"},
        {"api", api},
        {"status", status},
        {"bytes", bytes}
    };
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

ULONG WINAPI HttpSendHttpResponse_Hook(HANDLE queue,
                                       HTTP_REQUEST_ID request_id,
                                       ULONG flags,
                                       PHTTP_RESPONSE response,
                                       PVOID cache_policy,
                                       PULONG bytes_sent,
                                       PVOID reserved1,
                                       ULONG reserved2,
                                       PHTTP_LOG_FIELDS_DATA log_data,
                                       PVOID reserved3) {
    ULONG status_code = response ? response->StatusCode : 0;
    ULONG result = g_send_response(queue, request_id, flags, response, cache_policy, bytes_sent,
                                   reserved1, reserved2, log_data, reserved3);
    log_http_event("HttpSendHttpResponse", status_code, bytes_sent ? *bytes_sent : 0);
    return result;
}

ULONG WINAPI HttpSendResponseEntityBody_Hook(HANDLE queue,
                                             HTTP_REQUEST_ID request_id,
                                             ULONG flags,
                                             USHORT chunk_count,
                                             PHTTP_DATA_CHUNK data_chunks,
                                             PULONG bytes_sent,
                                             PVOID reserved1,
                                             ULONG reserved2,
                                             PHTTP_LOG_FIELDS_DATA log_data,
                                             PVOID reserved3) {
    ULONG result = g_send_entity(queue, request_id, flags, chunk_count, data_chunks, bytes_sent,
                                 reserved1, reserved2, log_data, reserved3);
    log_http_event("HttpSendResponseEntityBody", 0, bytes_sent ? *bytes_sent : 0);
    return result;
}

bool hook_http_sys(const char* name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(L"httpapi.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"httpapi.dll");
    }
    if (module == nullptr) {
        return false;
    }
    FARPROC proc = GetProcAddress(module, name);
    if (!proc) {
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

bool HttpSysHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void HttpSysHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool HttpSysHook::install_hooks() {
    return hook_http_sys("HttpSendHttpResponse", reinterpret_cast<void*>(&HttpSendHttpResponse_Hook),
                         reinterpret_cast<void**>(&g_send_response)) &&
           hook_http_sys("HttpSendResponseEntityBody", reinterpret_cast<void*>(&HttpSendResponseEntityBody_Hook),
                         reinterpret_cast<void**>(&g_send_entity));
}

void HttpSysHook::uninstall_hooks() {
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

bool HttpSysHook::initialize(const PluginContext&) {
    return false;
}

void HttpSysHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
