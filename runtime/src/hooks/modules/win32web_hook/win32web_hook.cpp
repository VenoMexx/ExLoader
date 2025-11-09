#include "exloader/runtime/hooks/modules/win32web_hook/win32web_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <minhook.h>
#include <WebServices.h>

#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

Win32WebHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using WsCreateListenerFn = HRESULT(WINAPI*)(const WS_LISTENER_PROPERTY*, ULONG, HANDLE, WS_LISTENER**);
using WsOpenListenerFn = HRESULT(WINAPI*)(WS_LISTENER*, WS_ENDPOINT_ADDRESS*, const WS_ASYNC_CONTEXT*, WS_ERROR*);
using WsStartListenerFn = HRESULT(WINAPI*)(WS_LISTENER*, const WS_ASYNC_CONTEXT*, WS_ERROR*);
using WsSendMessageFn = HRESULT(WINAPI*)(WS_CHANNEL*, WS_MESSAGE*, const WS_MESSAGE_DESCRIPTION*, const WS_MESSAGE_PROPERTY*, ULONG, const WS_ASYNC_CONTEXT*, WS_ERROR*);
using WsReceiveMessageFn = HRESULT(WINAPI*)(WS_CHANNEL*, WS_MESSAGE*, const WS_MESSAGE_DESCRIPTION**, ULONG, WS_MESSAGE_DESCRIPTION*, WS_MESSAGE_PROPERTY*, ULONG, ULONG*, const WS_ASYNC_CONTEXT*, WS_ERROR*);

WsCreateListenerFn g_create_listener = nullptr;
WsOpenListenerFn g_open_listener = nullptr;
WsStartListenerFn g_start_listener = nullptr;
WsSendMessageFn g_send_message = nullptr;
WsReceiveMessageFn g_receive_message = nullptr;

void log_ws_event(const char* api, HRESULT hr) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }
    nlohmann::json json{
        {"type", "network.win32web"},
        {"api", api},
        {"hr", hr}
    };
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

HRESULT WINAPI WsCreateListener_Hook(const WS_LISTENER_PROPERTY* properties,
                                     ULONG property_count,
                                     HANDLE security_token,
                                     WS_LISTENER** listener) {
    const HRESULT hr = g_create_listener(properties, property_count, security_token, listener);
    log_ws_event("WsCreateListener", hr);
    return hr;
}

HRESULT WINAPI WsOpenListener_Hook(WS_LISTENER* listener,
                                   WS_ENDPOINT_ADDRESS* address,
                                   const WS_ASYNC_CONTEXT* async_context,
                                   WS_ERROR* error) {
    const HRESULT hr = g_open_listener(listener, address, async_context, error);
    log_ws_event("WsOpenListener", hr);
    return hr;
}

HRESULT WINAPI WsStartListener_Hook(WS_LISTENER* listener,
                                    const WS_ASYNC_CONTEXT* async_context,
                                    WS_ERROR* error) {
    const HRESULT hr = g_start_listener(listener, async_context, error);
    log_ws_event("WsStartListener", hr);
    return hr;
}

HRESULT WINAPI WsSendMessage_Hook(WS_CHANNEL* channel,
                                  WS_MESSAGE* message,
                                  const WS_MESSAGE_DESCRIPTION* description,
                                  const WS_MESSAGE_PROPERTY* properties,
                                  ULONG property_count,
                                  const WS_ASYNC_CONTEXT* async_context,
                                  WS_ERROR* error) {
    const HRESULT hr = g_send_message(channel, message, description, properties, property_count,
                                      async_context, error);
    log_ws_event("WsSendMessage", hr);
    return hr;
}

HRESULT WINAPI WsReceiveMessage_Hook(WS_CHANNEL* channel,
                                     WS_MESSAGE* message,
                                     const WS_MESSAGE_DESCRIPTION** descriptions,
                                     ULONG count,
                                     WS_MESSAGE_DESCRIPTION* matched,
                                     WS_MESSAGE_PROPERTY* properties,
                                     ULONG property_count,
                                     ULONG* index,
                                     const WS_ASYNC_CONTEXT* async_context,
                                     WS_ERROR* error) {
    const HRESULT hr = g_receive_message(channel, message, descriptions, count, matched, properties,
                                         property_count, index, async_context, error);
    log_ws_event("WsReceiveMessage", hr);
    return hr;
}

bool hook_ws_api(const char* name, void* detour, void** original) {
    HMODULE module = GetModuleHandleW(L"webservices.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"webservices.dll");
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

bool Win32WebHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void Win32WebHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool Win32WebHook::install_hooks() {
    return hook_ws_api("WsCreateListener",
                       reinterpret_cast<void*>(&WsCreateListener_Hook),
                       reinterpret_cast<void**>(&g_create_listener)) &&
           hook_ws_api("WsOpenListener", reinterpret_cast<void*>(&WsOpenListener_Hook),
                       reinterpret_cast<void**>(&g_open_listener)) &&
           hook_ws_api("WsStartListener", reinterpret_cast<void*>(&WsStartListener_Hook),
                       reinterpret_cast<void**>(&g_start_listener)) &&
           hook_ws_api("WsSendMessage", reinterpret_cast<void*>(&WsSendMessage_Hook),
                       reinterpret_cast<void**>(&g_send_message)) &&
           hook_ws_api("WsReceiveMessage", reinterpret_cast<void*>(&WsReceiveMessage_Hook),
                       reinterpret_cast<void**>(&g_receive_message));
}

void Win32WebHook::uninstall_hooks() {
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

bool Win32WebHook::initialize(const PluginContext&) {
    return false;
}

void Win32WebHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
