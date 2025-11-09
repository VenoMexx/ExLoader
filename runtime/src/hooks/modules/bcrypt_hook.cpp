#include "exloader/runtime/hooks/modules/bcrypt_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>
#include <minhook.h>

#include <mutex>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/crypto/key_store.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

BCryptHook* g_instance = nullptr;
crypto::KeyStore g_key_store;
std::vector<void*> g_hook_targets;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

std::string narrow(LPCWSTR wide);

using BCryptOpenAlgorithmProviderFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
using BCryptGenerateSymmetricKeyFn = NTSTATUS(WINAPI*)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
using BCryptEncryptFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
using BCryptDecryptFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
using BCryptDestroyKeyFn = NTSTATUS(WINAPI*)(BCRYPT_KEY_HANDLE);

BCryptOpenAlgorithmProviderFn g_orig_open_alg = nullptr;
BCryptGenerateSymmetricKeyFn g_orig_gen_key = nullptr;
BCryptEncryptFn g_orig_encrypt = nullptr;
BCryptDecryptFn g_orig_decrypt = nullptr;
BCryptDestroyKeyFn g_orig_destroy_key = nullptr;

bool hook_api(LPCWSTR module_name, LPCSTR proc_name, void* detour, void** original) {
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

std::string ascii_preview(const void* data, std::size_t length, std::size_t max_chars = 512) {
    if (data == nullptr || length == 0) {
        return {};
    }
    const auto* bytes = reinterpret_cast<const unsigned char*>(data);
    std::string preview;
    const std::size_t limit = std::min<std::size_t>(length, max_chars);
    preview.reserve(limit);
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

void log_crypto_event(const char* api,
                      std::string_view direction,
                      std::string_view buffer_role,
                      BCRYPT_KEY_HANDLE key,
                      const void* buffer,
                      std::size_t length,
                      const void* iv,
                      std::size_t iv_length) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", direction},
        {"api", api},
        {"buffer_role", buffer_role}
    };
    json["key_handle"] = reinterpret_cast<std::uintptr_t>(key);

    if (auto metadata = g_key_store.metadata_for(key)) {
        json["key"] = {
            {"algorithm", metadata->algorithm},
            {"size", metadata->key_size}
        };
    }

    if (iv != nullptr && iv_length > 0) {
        json["iv_hex"] = hex_encode(iv, iv_length, g_instance->context()->max_payload_bytes);
        json["iv_len"] = iv_length;
    }

    if (buffer != nullptr && length > 0) {
        json["payload_hex"] = hex_encode(buffer, length, g_instance->context()->max_payload_bytes);
        json["payload_len"] = length;
        std::string preview = ascii_preview(buffer, length);
        if (!preview.empty()) {
            json["payload_text"] = preview;
        }
    }

    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

NTSTATUS WINAPI BCryptOpenAlgorithmProvider_Hook(BCRYPT_ALG_HANDLE* phAlgorithm,
                                                 LPCWSTR pszAlgId,
                                                 LPCWSTR pszImplementation,
                                                 ULONG dwFlags) {
    const NTSTATUS status = g_orig_open_alg(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
    if (NT_SUCCESS(status) && phAlgorithm != nullptr && *phAlgorithm != nullptr) {
        g_key_store.register_algorithm(*phAlgorithm, narrow(pszAlgId));
    }
    return status;
}

std::string narrow(LPCWSTR wide) {
    if (!wide) {
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

NTSTATUS WINAPI BCryptGenerateSymmetricKey_Hook(BCRYPT_ALG_HANDLE hAlgorithm,
                                                BCRYPT_KEY_HANDLE* phKey,
                                                PUCHAR pbKeyObject,
                                                ULONG cbKeyObject,
                                                PUCHAR pbSecret,
                                                ULONG cbSecret,
                                                ULONG dwFlags) {
    const NTSTATUS status = g_orig_gen_key(hAlgorithm, phKey, pbKeyObject, cbKeyObject, pbSecret,
                                           cbSecret, dwFlags);
    if (NT_SUCCESS(status) && phKey != nullptr && *phKey != nullptr && pbSecret != nullptr) {
        crypto::KeyMetadata meta{};
        if (auto alg = g_key_store.algorithm_for(hAlgorithm)) {
            meta.algorithm = *alg;
        }
        meta.key_hex = hex_encode(pbSecret, cbSecret, g_instance->context()->max_payload_bytes);
        meta.key_size = cbSecret;
        g_key_store.upsert_key(*phKey, std::move(meta));
    }
    return status;
}

NTSTATUS WINAPI BCryptEncrypt_Hook(BCRYPT_KEY_HANDLE hKey,
                                   PUCHAR pbInput,
                                   ULONG cbInput,
                                   VOID* pPaddingInfo,
                                   PUCHAR pbIV,
                                   ULONG cbIV,
                                   PUCHAR pbOutput,
                                   ULONG cbOutput,
                                   ULONG* pcbResult,
                                   ULONG dwFlags) {
    log_crypto_event("BCryptEncrypt", "crypto.encrypt", "plaintext", hKey, pbInput, cbInput,
                     pbIV, cbIV);
    NTSTATUS status = g_orig_encrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput,
                                     cbOutput, pcbResult, dwFlags);
    if (NT_SUCCESS(status) && pbOutput != nullptr && pcbResult != nullptr) {
        log_crypto_event("BCryptEncrypt", "crypto.encrypt", "ciphertext", hKey, pbOutput,
                         *pcbResult, pbIV, cbIV);
    }
    return status;
}

NTSTATUS WINAPI BCryptDecrypt_Hook(BCRYPT_KEY_HANDLE hKey,
                                   PUCHAR pbInput,
                                   ULONG cbInput,
                                   VOID* pPaddingInfo,
                                   PUCHAR pbIV,
                                   ULONG cbIV,
                                   PUCHAR pbOutput,
                                   ULONG cbOutput,
                                   ULONG* pcbResult,
                                   ULONG dwFlags) {
    log_crypto_event("BCryptDecrypt", "crypto.decrypt", "ciphertext", hKey, pbInput, cbInput,
                     pbIV, cbIV);
    NTSTATUS status = g_orig_decrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput,
                                     cbOutput, pcbResult, dwFlags);
    if (NT_SUCCESS(status) && pbOutput != nullptr && pcbResult != nullptr) {
        log_crypto_event("BCryptDecrypt", "crypto.decrypt", "plaintext", hKey, pbOutput,
                         *pcbResult, pbIV, cbIV);
    }
    return status;
}

NTSTATUS WINAPI BCryptDestroyKey_Hook(BCRYPT_KEY_HANDLE hKey) {
    g_key_store.remove_key(hKey);
    return g_orig_destroy_key(hKey);
}

}  // namespace

bool BCryptHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void BCryptHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool BCryptHook::install_hooks() {
    return hook_api(L"bcrypt.dll", "BCryptOpenAlgorithmProvider",
                    reinterpret_cast<void*>(&BCryptOpenAlgorithmProvider_Hook),
                    reinterpret_cast<void**>(&g_orig_open_alg)) &&
           hook_api(L"bcrypt.dll", "BCryptGenerateSymmetricKey",
                    reinterpret_cast<void*>(&BCryptGenerateSymmetricKey_Hook),
                    reinterpret_cast<void**>(&g_orig_gen_key)) &&
           hook_api(L"bcrypt.dll", "BCryptEncrypt",
                    reinterpret_cast<void*>(&BCryptEncrypt_Hook),
                    reinterpret_cast<void**>(&g_orig_encrypt)) &&
           hook_api(L"bcrypt.dll", "BCryptDecrypt",
                    reinterpret_cast<void*>(&BCryptDecrypt_Hook),
                    reinterpret_cast<void**>(&g_orig_decrypt)) &&
           hook_api(L"bcrypt.dll", "BCryptDestroyKey",
                    reinterpret_cast<void*>(&BCryptDestroyKey_Hook),
                    reinterpret_cast<void**>(&g_orig_destroy_key));
}

void BCryptHook::uninstall_hooks() {
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

bool BCryptHook::initialize(const PluginContext&) {
    return false;
}

void BCryptHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
