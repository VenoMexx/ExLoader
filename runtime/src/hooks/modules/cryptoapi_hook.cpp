#include "exloader/runtime/hooks/modules/cryptoapi_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>
#include <minhook.h>

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <cstdio>
#include <cstdint>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/crypto/key_store.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

CryptoApiHook* g_instance = nullptr;
crypto::KeyStore g_key_store;
std::vector<void*> g_hook_targets;

using CryptImportKeyFn = BOOL(WINAPI*)(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
using CryptEncryptFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*, DWORD);
using CryptDecryptFn = BOOL(WINAPI*)(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
using CryptDestroyKeyFn = BOOL(WINAPI*)(HCRYPTKEY);
using CryptGetKeyParamFn = BOOL(WINAPI*)(HCRYPTKEY, DWORD, BYTE*, DWORD*, DWORD);
using CryptCreateHashFn = BOOL(WINAPI*)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
using CryptHashDataFn = BOOL(WINAPI*)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
using CryptGetHashParamFn = BOOL(WINAPI*)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
using CryptDestroyHashFn = BOOL(WINAPI*)(HCRYPTHASH);

CryptImportKeyFn g_orig_import = nullptr;
CryptEncryptFn g_orig_encrypt = nullptr;
CryptDecryptFn g_orig_decrypt = nullptr;
CryptDestroyKeyFn g_orig_destroy = nullptr;
CryptGetKeyParamFn g_get_key_param = nullptr;
CryptCreateHashFn g_orig_create_hash = nullptr;
CryptHashDataFn g_orig_hash_data = nullptr;
CryptGetHashParamFn g_orig_get_hash_param = nullptr;
CryptDestroyHashFn g_orig_destroy_hash = nullptr;

struct HashInfo {
    std::string algorithm;
    std::vector<uint8_t> preview;
};

std::unordered_map<HCRYPTHASH, HashInfo> g_hashes;
std::mutex g_hash_mutex;

std::string algid_to_string(DWORD algid) {
    switch (algid) {
        case CALG_AES_128: return "AES-128";
        case CALG_AES_192: return "AES-192";
        case CALG_AES_256: return "AES-256";
        case CALG_3DES: return "3DES";
        case CALG_RC4: return "RC4";
        case CALG_DES: return "DES";
        default: {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "ALG_%lu", static_cast<unsigned long>(algid));
            return buffer;
        }
    }
}

std::string hash_algid_to_string(ALG_ID algid) {
    switch (algid) {
        case CALG_MD5: return "MD5";
#if defined(CALG_SHA)
        case CALG_SHA:
#endif
#if defined(CALG_SHA1) && (!defined(CALG_SHA) || (CALG_SHA1 != CALG_SHA))
        case CALG_SHA1:
#endif
            return "SHA1";
        case CALG_SHA_256: return "SHA-256";
        case CALG_SHA_384: return "SHA-384";
        case CALG_SHA_512: return "SHA-512";
        case CALG_HMAC: return "HMAC";
        default: {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "HASH_%lu", static_cast<unsigned long>(algid));
            return buffer;
        }
    }
}

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

void log_crypto(const char* api,
                std::string_view direction,
                std::string_view buffer_role,
                HCRYPTKEY key,
                const void* buffer,
                std::size_t length) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", direction},
        {"api", api},
        {"buffer_role", buffer_role}
    };
    json["key_handle"] = static_cast<std::uintptr_t>(key);

    if (auto metadata = g_key_store.metadata_for(reinterpret_cast<void*>(key))) {
        json["key"] = {
            {"algorithm", metadata->algorithm},
            {"size", metadata->key_size}
        };
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

BOOL WINAPI CryptImportKey_Hook(HCRYPTPROV hProv,
                                const BYTE* pbData,
                                DWORD dwDataLen,
                                HCRYPTKEY hPubKey,
                                DWORD dwFlags,
                                HCRYPTKEY* phKey) {
    const BOOL result = g_orig_import(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
    if (result && phKey != nullptr && *phKey != HCRYPTKEY{}) {
        DWORD alg_id = 0;
        DWORD alg_size = sizeof(alg_id);
        if (g_get_key_param != nullptr && g_get_key_param(*phKey, KP_ALGID,
                                                          reinterpret_cast<BYTE*>(&alg_id), &alg_size,
                                                          0)) {
            crypto::KeyMetadata meta{};
            meta.algorithm = algid_to_string(alg_id);
            meta.key_hex = hex_encode(pbData, dwDataLen, g_instance->context()->max_payload_bytes);
            meta.key_size = dwDataLen;
            g_key_store.upsert_key(reinterpret_cast<void*>(*phKey), std::move(meta));
        }
    }
    return result;
}

BOOL WINAPI CryptEncrypt_Hook(HCRYPTKEY hKey,
                              HCRYPTHASH hHash,
                              BOOL final,
                              DWORD dwFlags,
                              BYTE* pbData,
                              DWORD* pdwDataLen,
                              DWORD dwBufLen) {
    std::vector<uint8_t> plaintext;
    if (pbData != nullptr && pdwDataLen != nullptr) {
        plaintext.assign(pbData, pbData + *pdwDataLen);
        log_crypto("CryptEncrypt", "crypto.encrypt", "plaintext", hKey,
                   plaintext.data(), plaintext.size());
    }
    BOOL result = g_orig_encrypt(hKey, hHash, final, dwFlags, pbData, pdwDataLen, dwBufLen);
    if (result && pbData != nullptr && pdwDataLen != nullptr) {
        log_crypto("CryptEncrypt", "crypto.encrypt", "ciphertext", hKey,
                   pbData, *pdwDataLen);
    }
    return result;
}

BOOL WINAPI CryptDecrypt_Hook(HCRYPTKEY hKey,
                              HCRYPTHASH hHash,
                              BOOL final,
                              DWORD dwFlags,
                              BYTE* pbData,
                              DWORD* pdwDataLen) {
    std::vector<uint8_t> ciphertext;
    if (pbData != nullptr && pdwDataLen != nullptr) {
        ciphertext.assign(pbData, pbData + *pdwDataLen);
        log_crypto("CryptDecrypt", "crypto.decrypt", "ciphertext", hKey,
                   ciphertext.data(), ciphertext.size());
    }
    BOOL result = g_orig_decrypt(hKey, hHash, final, dwFlags, pbData, pdwDataLen);
    if (result && pbData != nullptr && pdwDataLen != nullptr) {
        log_crypto("CryptDecrypt", "crypto.decrypt", "plaintext", hKey, pbData, *pdwDataLen);
    }
    return result;
}

BOOL WINAPI CryptDestroyKey_Hook(HCRYPTKEY hKey) {
    g_key_store.remove_key(reinterpret_cast<void*>(hKey));
    return g_orig_destroy(hKey);
}

void log_hash_event(const char* api,
                    std::string_view stage,
                    HCRYPTHASH hash,
                    const void* buffer,
                    std::size_t length) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", stage},
        {"api", api},
        {"hash_handle", static_cast<std::uintptr_t>(hash)}
    };

    {
        std::lock_guard<std::mutex> lock(g_hash_mutex);
        auto it = g_hashes.find(hash);
        if (it != g_hashes.end()) {
            nlohmann::json hash_info;
            hash_info["algorithm"] = it->second.algorithm;
            json["hash"] = std::move(hash_info);
        }
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

BOOL WINAPI CryptCreateHash_Hook(HCRYPTPROV hProv,
                                 ALG_ID Algid,
                                 HCRYPTKEY hKey,
                                 DWORD dwFlags,
                                 HCRYPTHASH* phHash) {
    BOOL result = g_orig_create_hash(hProv, Algid, hKey, dwFlags, phHash);
    if (result && phHash != nullptr && *phHash != 0) {
        {
            std::lock_guard<std::mutex> lock(g_hash_mutex);
            HashInfo info;
            info.algorithm = hash_algid_to_string(Algid);
            g_hashes[*phHash] = std::move(info);
        }
        log_hash_event("CryptCreateHash", "crypto.hash.create", *phHash, nullptr, 0);
    }
    return result;
}

BOOL WINAPI CryptHashData_Hook(HCRYPTHASH hHash,
                               const BYTE* pbData,
                               DWORD dwDataLen,
                               DWORD dwFlags) {
    if (pbData != nullptr && dwDataLen > 0) {
        {
            std::lock_guard<std::mutex> lock(g_hash_mutex);
            auto it = g_hashes.find(hHash);
            if (it != g_hashes.end()) {
                std::size_t max_bytes = g_instance && g_instance->context()
                                            ? g_instance->context()->max_payload_bytes
                                            : 4096;
                if (it->second.preview.size() < max_bytes) {
                    std::size_t remaining = max_bytes - it->second.preview.size();
                    std::size_t to_copy = std::min<std::size_t>(remaining, dwDataLen);
                    it->second.preview.insert(it->second.preview.end(), pbData, pbData + to_copy);
                }
            }
        }
        log_hash_event("CryptHashData", "crypto.hash.update", hHash, pbData, dwDataLen);
    }
    return g_orig_hash_data(hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI CryptGetHashParam_Hook(HCRYPTHASH hHash,
                                   DWORD dwParam,
                                   BYTE* pbData,
                                   DWORD* pdwDataLen,
                                   DWORD dwFlags) {
    BOOL result = g_orig_get_hash_param(hHash, dwParam, pbData, pdwDataLen, dwFlags);
    if (result && dwParam == HP_HASHVAL && pbData != nullptr && pdwDataLen != nullptr) {
        log_hash_event("CryptGetHashParam", "crypto.hash.digest", hHash, pbData, *pdwDataLen);
    }
    return result;
}

BOOL WINAPI CryptDestroyHash_Hook(HCRYPTHASH hHash) {
    {
        std::lock_guard<std::mutex> lock(g_hash_mutex);
        g_hashes.erase(hHash);
    }
    log_hash_event("CryptDestroyHash", "crypto.hash.destroy", hHash, nullptr, 0);
    return g_orig_destroy_hash(hHash);
}

}  // namespace

bool CryptoApiHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    HMODULE advapi = GetModuleHandleW(L"advapi32.dll");
    if (advapi == nullptr) {
        advapi = LoadLibraryW(L"advapi32.dll");
    }
    if (advapi != nullptr) {
        g_get_key_param = reinterpret_cast<CryptGetKeyParamFn>(GetProcAddress(advapi, "CryptGetKeyParam"));
    }
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void CryptoApiHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool CryptoApiHook::install_hooks() {
    return hook_api(L"advapi32.dll", "CryptImportKey",
                    reinterpret_cast<void*>(&CryptImportKey_Hook),
                    reinterpret_cast<void**>(&g_orig_import)) &&
           hook_api(L"advapi32.dll", "CryptEncrypt",
                    reinterpret_cast<void*>(&CryptEncrypt_Hook),
                    reinterpret_cast<void**>(&g_orig_encrypt)) &&
           hook_api(L"advapi32.dll", "CryptDecrypt",
                    reinterpret_cast<void*>(&CryptDecrypt_Hook),
                    reinterpret_cast<void**>(&g_orig_decrypt)) &&
           hook_api(L"advapi32.dll", "CryptDestroyKey",
                    reinterpret_cast<void*>(&CryptDestroyKey_Hook),
                    reinterpret_cast<void**>(&g_orig_destroy)) &&
           hook_api(L"advapi32.dll", "CryptCreateHash",
                    reinterpret_cast<void*>(&CryptCreateHash_Hook),
                    reinterpret_cast<void**>(&g_orig_create_hash)) &&
           hook_api(L"advapi32.dll", "CryptHashData",
                    reinterpret_cast<void*>(&CryptHashData_Hook),
                    reinterpret_cast<void**>(&g_orig_hash_data)) &&
           hook_api(L"advapi32.dll", "CryptGetHashParam",
                    reinterpret_cast<void*>(&CryptGetHashParam_Hook),
                    reinterpret_cast<void**>(&g_orig_get_hash_param)) &&
           hook_api(L"advapi32.dll", "CryptDestroyHash",
                    reinterpret_cast<void*>(&CryptDestroyHash_Hook),
                    reinterpret_cast<void**>(&g_orig_destroy_hash));
}

void CryptoApiHook::uninstall_hooks() {
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

bool CryptoApiHook::initialize(const PluginContext&) {
    return false;
}

void CryptoApiHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
