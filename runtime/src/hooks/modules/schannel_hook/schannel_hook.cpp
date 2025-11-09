#include "exloader/runtime/hooks/modules/schannel_hook/schannel_hook.hpp"

#if defined(_WIN32)

#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <sspi.h>
#include <minhook.h>

#include <mutex>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

SchannelHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using EncryptMessageFn = SECURITY_STATUS(WINAPI*)(PCtxtHandle, unsigned long, PSecBufferDesc, unsigned long);
using DecryptMessageFn = SECURITY_STATUS(WINAPI*)(PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long*);

EncryptMessageFn g_encrypt_message = nullptr;
DecryptMessageFn g_decrypt_message = nullptr;

void log_schannel_event(const char* api, SECURITY_STATUS status, const SecBufferDesc* buffers) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", "network.schannel"},
        {"api", api},
        {"status", status}
    };

    if (buffers && buffers->cBuffers > 0 && buffers->pBuffers) {
        const SecBuffer& buffer = buffers->pBuffers[0];
        if (buffer.cbBuffer > 0 && buffer.pvBuffer) {
            json["payload_hex"] = hex_encode(buffer.pvBuffer, buffer.cbBuffer, g_instance->context()->max_payload_bytes);
            json["payload_len"] = buffer.cbBuffer;
        }
    }

    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

SECURITY_STATUS WINAPI EncryptMessage_Hook(PCtxtHandle context,
                                           unsigned long quality_of_protection,
                                           PSecBufferDesc message,
                                           unsigned long sequence_number) {
    SECURITY_STATUS status = g_encrypt_message(context, quality_of_protection, message, sequence_number);
    log_schannel_event("EncryptMessage", status, message);
    return status;
}

SECURITY_STATUS WINAPI DecryptMessage_Hook(PCtxtHandle context,
                                           PSecBufferDesc message,
                                           unsigned long sequence_number,
                                           unsigned long* quality_of_protection) {
    SECURITY_STATUS status = g_decrypt_message(context, message, sequence_number, quality_of_protection);
    log_schannel_event("DecryptMessage", status, message);
    return status;
}

bool hook_schannel_api(const char* name, void* detour, void** original) {
    HMODULE secur32 = GetModuleHandleW(L"secur32.dll");
    if (secur32 == nullptr) {
        secur32 = LoadLibraryW(L"secur32.dll");
    }
    if (secur32 == nullptr) {
        return false;
    }
    FARPROC proc = GetProcAddress(secur32, name);
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

bool SchannelHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void SchannelHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool SchannelHook::install_hooks() {
    return hook_schannel_api("EncryptMessage", reinterpret_cast<void*>(&EncryptMessage_Hook),
                             reinterpret_cast<void**>(&g_encrypt_message)) &&
           hook_schannel_api("DecryptMessage", reinterpret_cast<void*>(&DecryptMessage_Hook),
                             reinterpret_cast<void**>(&g_decrypt_message));
}

void SchannelHook::uninstall_hooks() {
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

bool SchannelHook::initialize(const PluginContext&) {
    return false;
}

void SchannelHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
