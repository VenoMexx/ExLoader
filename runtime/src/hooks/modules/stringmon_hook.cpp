#include "exloader/runtime/hooks/modules/stringmon_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <minhook.h>

#include <cwctype>
#include <mutex>
#include <string>
#include <vector>
#include <cstdint>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {

namespace {

StringMonHook* g_instance = nullptr;
std::vector<void*> g_hook_targets;

using WtoMBFn = int(WINAPI*)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
using MBtoWFn = int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int);
using CharUpperBuffWFn = DWORD(WINAPI*)(LPWSTR, DWORD);
using LStrCpyWFn = LPWSTR(WINAPI*)(LPWSTR, LPCWSTR);
using LStrCpyNWFn = LPWSTR(WINAPI*)(LPWSTR, LPCWSTR, int);
using LStrCatWFn = LPWSTR(WINAPI*)(LPWSTR, LPCWSTR);
using LStrLenWFn = int(WINAPI*)(LPCWSTR);

WtoMBFn g_orig_wide_to_mb = nullptr;
MBtoWFn g_orig_mb_to_wide = nullptr;
CharUpperBuffWFn g_orig_upper = nullptr;
LStrCpyWFn g_orig_lstrcpy = nullptr;
LStrCpyNWFn g_orig_lstrcpyn = nullptr;
LStrCatWFn g_orig_lstrcat = nullptr;
LStrLenWFn g_orig_lstrlen = nullptr;

std::wstring capture_wide(const wchar_t* buf, int len, std::size_t max_chars) {
    if (buf == nullptr) {
        return {};
    }
    std::size_t count = 0;
    if (len < 0) {
        while (buf[count] != L'\0' && count < max_chars) {
            ++count;
        }
    } else {
        count = std::min<std::size_t>(static_cast<std::size_t>(len), max_chars);
    }
    return std::wstring(buf, buf + count);
}

std::string capture_narrow(const char* buf, int len, std::size_t max_chars) {
    if (buf == nullptr) {
        return {};
    }
    std::size_t count = 0;
    if (len < 0) {
        while (buf[count] != '\0' && count < max_chars) {
            ++count;
        }
    } else {
        count = std::min<std::size_t>(static_cast<std::size_t>(len), max_chars);
    }
    return std::string(buf, buf + count);
}

std::string utf8_from_wstring(const std::wstring& input) {
    std::string out;
    out.reserve(input.size());
    for (wchar_t wc : input) {
        unsigned int code = static_cast<unsigned int>(wc);
        if (code < 0x80) {
            out.push_back(static_cast<char>(code));
        } else if (code < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (code >> 6)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (code >> 12)));
            out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
        }
    }
    return out;
}

void log_string_event(const char* api,
                      std::string_view stage,
                      const wchar_t* wide_buf,
                      int wide_len,
                      const char* narrow_buf,
                      int narrow_len) {
    if (g_instance == nullptr || g_instance->context() == nullptr || g_instance->context()->logger == nullptr) {
        return;
    }

    nlohmann::json json{
        {"type", stage},
        {"api", api}
    };

    std::size_t max_bytes = g_instance->context()->max_payload_bytes;
    std::size_t max_chars = max_bytes / sizeof(wchar_t);
    if (wide_buf && wide_len != 0) {
        auto wide = capture_wide(wide_buf, wide_len, max_chars);
        if (!wide.empty()) {
            json["wide_hex"] = hex_encode(wide.data(), wide.size() * sizeof(wchar_t), max_bytes);
        }
    }
    if (narrow_buf && narrow_len != 0) {
        auto narrow = capture_narrow(narrow_buf, narrow_len, max_bytes);
        if (!narrow.empty()) {
            json["narrow_hex"] = hex_encode(narrow.data(), narrow.size(), max_bytes);
        }
    }
    append_caller(json, resolve_caller(EXL_RETURN_ADDRESS()));
    g_instance->context()->logger->log(std::move(json));
}

template <typename Fn>
bool hook_api(LPCWSTR module_name, LPCSTR proc_name, Fn detour, Fn* original) {
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
    void* target = reinterpret_cast<void*>(proc);
    if (MH_CreateHook(target, reinterpret_cast<void*>(detour), reinterpret_cast<void**>(original)) != MH_OK) {
        return false;
    }
    if (MH_EnableHook(target) != MH_OK) {
        MH_RemoveHook(target);
        return false;
    }
    g_hook_targets.push_back(target);
    return true;
}

int WINAPI WideCharToMultiByte_Hook(UINT CodePage,
                                    DWORD dwFlags,
                                    LPCWCH lpWideCharStr,
                                    int cchWideChar,
                                    LPSTR lpMultiByteStr,
                                    int cbMultiByte,
                                    LPCCH lpDefaultChar,
                                    LPBOOL lpUsedDefaultChar) {
    int result = g_orig_wide_to_mb(CodePage, dwFlags, lpWideCharStr, cchWideChar,
                                   lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
    log_string_event("WideCharToMultiByte", "string.convert", lpWideCharStr,
                     cchWideChar, lpMultiByteStr, result > 0 ? result : 0);
    return result;
}

int WINAPI MultiByteToWideChar_Hook(UINT CodePage,
                                    DWORD dwFlags,
                                    LPCCH lpMultiByteStr,
                                    int cbMultiByte,
                                    LPWSTR lpWideCharStr,
                                    int cchWideChar) {
    int result = g_orig_mb_to_wide(CodePage, dwFlags, lpMultiByteStr, cbMultiByte,
                                   lpWideCharStr, cchWideChar);
    log_string_event("MultiByteToWideChar", "string.convert", lpWideCharStr,
                     result > 0 ? result : cchWideChar, lpMultiByteStr, cbMultiByte);
    return result;
}

DWORD WINAPI CharUpperBuffW_Hook(LPWSTR lpsz, DWORD cchLength) {
    log_string_event("CharUpperBuffW", "string.transform.pre", lpsz, cchLength, nullptr, 0);
    DWORD result = g_orig_upper(lpsz, cchLength);
    log_string_event("CharUpperBuffW", "string.transform.post", lpsz, cchLength, nullptr, 0);
    return result;
}

LPWSTR WINAPI lstrcpyW_Hook(LPWSTR dst, LPCWSTR src) {
    LPWSTR ret = g_orig_lstrcpy(dst, src);
    log_string_event("lstrcpyW", "string.copy", src, -1, nullptr, 0);
    return ret;
}

LPWSTR WINAPI lstrcpynW_Hook(LPWSTR dst, LPCWSTR src, int cchMax) {
    LPWSTR ret = g_orig_lstrcpyn(dst, src, cchMax);
    log_string_event("lstrcpynW", "string.copy", src, cchMax, nullptr, 0);
    return ret;
}

LPWSTR WINAPI lstrcatW_Hook(LPWSTR dst, LPCWSTR src) {
    LPWSTR ret = g_orig_lstrcat(dst, src);
    log_string_event("lstrcatW", "string.concat", src, -1, nullptr, 0);
    return ret;
}

}  // namespace

bool StringMonHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;
    hooks_installed_ = install_hooks();
    return hooks_installed_;
}

void StringMonHook::shutdown() {
    uninstall_hooks();
    g_instance = nullptr;
    context_ = nullptr;
}

bool StringMonHook::install_hooks() {
    return hook_api(L"kernel32.dll", "WideCharToMultiByte",
                    &WideCharToMultiByte_Hook, &g_orig_wide_to_mb) &&
           hook_api(L"kernel32.dll", "MultiByteToWideChar",
                    &MultiByteToWideChar_Hook, &g_orig_mb_to_wide) &&
           hook_api(L"user32.dll", "CharUpperBuffW",
                    &CharUpperBuffW_Hook, &g_orig_upper) &&
           hook_api(L"kernel32.dll", "lstrcpyW",
                    &lstrcpyW_Hook, &g_orig_lstrcpy) &&
           hook_api(L"kernel32.dll", "lstrcpynW",
                    &lstrcpynW_Hook, &g_orig_lstrcpyn) &&
           hook_api(L"kernel32.dll", "lstrcatW",
                    &lstrcatW_Hook, &g_orig_lstrcat) &&
           true;
}

void StringMonHook::uninstall_hooks() {
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

bool StringMonHook::initialize(const PluginContext&) { return false; }
void StringMonHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
