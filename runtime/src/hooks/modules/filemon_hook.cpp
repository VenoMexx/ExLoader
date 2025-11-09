#include "exloader/runtime/hooks/modules/filemon_hook.hpp"

#if defined(_WIN32)

#include <windows.h>
#include <winreg.h>
#include <minhook.h>

#include <algorithm>
#include <cwchar>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/event_utils.hpp"

namespace exloader::runtime::hooks::modules {
namespace {

FileMonHook* g_instance = nullptr;

struct FileHandleInfo {
    std::wstring path;
    DWORD access{0};
    DWORD share{0};
    DWORD disposition{0};
    DWORD flags{0};
};

struct RegHandleInfo {
    std::wstring path;
};

std::mutex g_file_mutex;
std::mutex g_reg_mutex;
std::mutex g_find_mutex;

std::vector<void*> g_hook_targets;

using CreateFileW_t = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFile_t = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFile_t = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using CloseHandle_t = BOOL(WINAPI*)(HANDLE);
using DeleteFileW_t = BOOL(WINAPI*)(LPCWSTR);
using MoveFileExW_t = BOOL(WINAPI*)(LPCWSTR, LPCWSTR, DWORD);
using GetFileAttributesW_t = DWORD(WINAPI*)(LPCWSTR);
using GetFileAttributesExW_t = BOOL(WINAPI*)(LPCWSTR, GET_FILEEX_INFO_LEVELS, LPVOID);
using GetModuleFileNameW_t = DWORD(WINAPI*)(HMODULE, LPWSTR, DWORD);
using FindFirstFileW_t = HANDLE(WINAPI*)(LPCWSTR, LPWIN32_FIND_DATAW);
using FindNextFileW_t = BOOL(WINAPI*)(HANDLE, LPWIN32_FIND_DATAW);
using FindClose_t = BOOL(WINAPI*)(HANDLE);

using RegOpenKeyExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegCreateKeyExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
                                          LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
using RegSetValueExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
using RegQueryValueExW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegDeleteKeyW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
using RegDeleteValueW_t = LSTATUS(WINAPI*)(HKEY, LPCWSTR);
using RegCloseKey_t = LSTATUS(WINAPI*)(HKEY);

CreateFileW_t g_orig_CreateFileW = nullptr;
ReadFile_t g_orig_ReadFile = nullptr;
WriteFile_t g_orig_WriteFile = nullptr;
CloseHandle_t g_orig_CloseHandle = nullptr;
DeleteFileW_t g_orig_DeleteFileW = nullptr;
MoveFileExW_t g_orig_MoveFileExW = nullptr;
GetFileAttributesW_t g_orig_GetFileAttributesW = nullptr;
GetFileAttributesExW_t g_orig_GetFileAttributesExW = nullptr;
GetModuleFileNameW_t g_orig_GetModuleFileNameW = nullptr;
FindFirstFileW_t g_orig_FindFirstFileW = nullptr;
FindNextFileW_t g_orig_FindNextFileW = nullptr;
FindClose_t g_orig_FindClose = nullptr;

struct FindHandleInfo {
    std::wstring pattern;
};

std::unordered_map<std::uintptr_t, FileHandleInfo> g_file_handles;
std::unordered_map<std::uintptr_t, RegHandleInfo> g_reg_handles;
std::unordered_map<std::uintptr_t, FindHandleInfo> g_find_handles;

RegOpenKeyExW_t g_orig_RegOpenKeyExW = nullptr;
RegCreateKeyExW_t g_orig_RegCreateKeyExW = nullptr;
RegSetValueExW_t g_orig_RegSetValueExW = nullptr;
RegQueryValueExW_t g_orig_RegQueryValueExW = nullptr;
RegDeleteKeyW_t g_orig_RegDeleteKeyW = nullptr;
RegDeleteValueW_t g_orig_RegDeleteValueW = nullptr;
RegCloseKey_t g_orig_RegCloseKey = nullptr;

const PluginContext* get_context() {
    return g_instance ? g_instance->context() : nullptr;
}

std::size_t payload_limit() {
    const auto* ctx = get_context();
    if (ctx && ctx->max_payload_bytes > 0) {
        return ctx->max_payload_bytes;
    }
    return 4096;
}

std::string utf8_from_wide(const std::wstring& wide) {
    if (wide.empty()) {
        return {};
    }
    int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                                     static_cast<int>(wide.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                        static_cast<int>(wide.size()),
                        result.data(), needed, nullptr, nullptr);
    return result;
}

std::wstring widen(const wchar_t* value) {
    return value ? std::wstring(value) : std::wstring();
}

void log_event(std::string_view operation, nlohmann::json payload) {
    const auto* ctx = get_context();
    if (!ctx || !ctx->logger) {
        return;
    }
    payload["type"] = "filesystem.filemon";
    payload["operation"] = operation;
    ctx->logger->log(std::move(payload));
}

std::optional<FileHandleInfo> lookup_file_info(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    std::lock_guard lock(g_file_mutex);
    auto it = g_file_handles.find(reinterpret_cast<std::uintptr_t>(handle));
    if (it == g_file_handles.end()) {
        return std::nullopt;
    }
    return it->second;
}

void store_file_info(HANDLE handle, FileHandleInfo info) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    std::lock_guard lock(g_file_mutex);
    g_file_handles[reinterpret_cast<std::uintptr_t>(handle)] = std::move(info);
}

void erase_file_info(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    std::lock_guard lock(g_file_mutex);
    g_file_handles.erase(reinterpret_cast<std::uintptr_t>(handle));
}

std::optional<FindHandleInfo> lookup_find_info(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    std::lock_guard lock(g_find_mutex);
    auto it = g_find_handles.find(reinterpret_cast<std::uintptr_t>(handle));
    if (it == g_find_handles.end()) {
        return std::nullopt;
    }
    return it->second;
}

void store_find_info(HANDLE handle, FindHandleInfo info) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    std::lock_guard lock(g_find_mutex);
    g_find_handles[reinterpret_cast<std::uintptr_t>(handle)] = std::move(info);
}

void erase_find_info(HANDLE handle) {
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    std::lock_guard lock(g_find_mutex);
    g_find_handles.erase(reinterpret_cast<std::uintptr_t>(handle));
}

std::wstring root_name_for(HKEY key) {
    if (key == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
    if (key == HKEY_CURRENT_USER) return L"HKEY_CURRENT_USER";
    if (key == HKEY_LOCAL_MACHINE) return L"HKEY_LOCAL_MACHINE";
    if (key == HKEY_USERS) return L"HKEY_USERS";
    if (key == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
    if (key == HKEY_PERFORMANCE_DATA) return L"HKEY_PERFORMANCE_DATA";
    if (key == HKEY_PERFORMANCE_NLSTEXT) return L"HKEY_PERFORMANCE_NLSTEXT";
    if (key == HKEY_PERFORMANCE_TEXT) return L"HKEY_PERFORMANCE_TEXT";
    return {};
}

std::wstring describe_hkey(HKEY key) {
    if (!key) {
        return L"(null)";
    }
    if (auto root = root_name_for(key); !root.empty()) {
        return root;
    }
    {
        std::lock_guard lock(g_reg_mutex);
        auto it = g_reg_handles.find(reinterpret_cast<std::uintptr_t>(key));
        if (it != g_reg_handles.end()) {
            return it->second.path;
        }
    }
    wchar_t buffer[32];
    swprintf(buffer, 32, L"%p", key);
    return buffer;
}

void store_reg_info(HKEY key, std::wstring path) {
    if (!key) {
        return;
    }
    std::lock_guard lock(g_reg_mutex);
    g_reg_handles[reinterpret_cast<std::uintptr_t>(key)] = RegHandleInfo{std::move(path)};
}

void erase_reg_info(HKEY key) {
    if (!key) {
        return;
    }
    std::lock_guard lock(g_reg_mutex);
    g_reg_handles.erase(reinterpret_cast<std::uintptr_t>(key));
}

std::wstring combine_key_path(HKEY parent, std::wstring_view subkey) {
    std::wstring base = describe_hkey(parent);
    if (base.empty()) {
        base = L"(unknown)";
    }
    if (!subkey.empty()) {
        if (base.back() != L'\\') {
            base.push_back(L'\\');
        }
        base.append(subkey);
    }
    return base;
}

std::string preview_buffer(const void* data, std::size_t length) {
    if (!data || length == 0) {
        return {};
    }
    const std::size_t limit = payload_limit();
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    bool printable = std::all_of(bytes, bytes + std::min(length, static_cast<std::size_t>(32)),
                                 [](std::uint8_t ch) {
                                     return ch >= 0x20 && ch <= 0x7E;
                                 });
    if (printable) {
        std::string text(bytes, bytes + std::min(length, limit));
        if (text.size() < length) {
            text.append("...");
        }
        return text;
    }
    return hooks::hex_encode(data, length, limit);
}

template <typename T>
bool hook_api(const wchar_t* module_name, const char* proc_name, T detour, T* original) {
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

HANDLE WINAPI CreateFileW_detour(LPCWSTR filename,
                                 DWORD desired_access,
                                 DWORD share_mode,
                                 LPSECURITY_ATTRIBUTES security,
                                 DWORD creation_disposition,
                                 DWORD flags_and_attributes,
                                 HANDLE template_file) {
    HANDLE handle = g_orig_CreateFileW(filename, desired_access, share_mode, security,
                                       creation_disposition, flags_and_attributes, template_file);
    DWORD last_error = GetLastError();

    if (handle != INVALID_HANDLE_VALUE) {
        FileHandleInfo info{
            .path = widen(filename),
            .access = desired_access,
            .share = share_mode,
            .disposition = creation_disposition,
            .flags = flags_and_attributes
        };
        store_file_info(handle, std::move(info));
    }

    nlohmann::json event;
    event["path"] = utf8_from_wide(widen(filename));
    event["desired_access"] = desired_access;
    event["share_mode"] = share_mode;
    event["disposition"] = creation_disposition;
    event["flags"] = flags_and_attributes;
    event["result"] = handle != INVALID_HANDLE_VALUE ? "success" : "failure";
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("create", std::move(event));

    SetLastError(last_error);
    return handle;
}

BOOL WINAPI ReadFile_detour(HANDLE file, LPVOID buffer, DWORD to_read,
                            LPDWORD read, LPOVERLAPPED overlapped) {
    auto info = lookup_file_info(file);
    BOOL ok = g_orig_ReadFile(file, buffer, to_read, read, overlapped);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["handle"] = reinterpret_cast<std::uintptr_t>(file);
    if (info) {
        event["path"] = utf8_from_wide(info->path);
    }
    event["requested_bytes"] = to_read;
    event["success"] = ok != FALSE;
    DWORD bytes_read = (read != nullptr) ? *read : 0;
    event["bytes_transferred"] = bytes_read;
    if (ok && buffer && bytes_read > 0) {
        event["payload_preview"] = preview_buffer(buffer, bytes_read);
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("read", std::move(event));

    SetLastError(last_error);
    return ok;
}

BOOL WINAPI WriteFile_detour(HANDLE file, LPCVOID buffer, DWORD to_write,
                             LPDWORD written, LPOVERLAPPED overlapped) {
    auto info = lookup_file_info(file);
    BOOL ok = g_orig_WriteFile(file, buffer, to_write, written, overlapped);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["handle"] = reinterpret_cast<std::uintptr_t>(file);
    if (info) {
        event["path"] = utf8_from_wide(info->path);
    }
    event["requested_bytes"] = to_write;
    event["success"] = ok != FALSE;
    DWORD bytes_written = (written != nullptr) ? *written : 0;
    event["bytes_transferred"] = bytes_written;
    if (buffer && to_write > 0) {
        event["payload_preview"] = preview_buffer(buffer, to_write);
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("write", std::move(event));

    SetLastError(last_error);
    return ok;
}

BOOL WINAPI CloseHandle_detour(HANDLE handle) {
    auto info = lookup_file_info(handle);
    BOOL ok = g_orig_CloseHandle(handle);
    DWORD last_error = GetLastError();

    if (ok) {
        erase_file_info(handle);
    }

    // Only log if this is a file handle we're tracking
    if (info) {
        nlohmann::json event;
        event["handle"] = reinterpret_cast<std::uintptr_t>(handle);
        event["success"] = ok != FALSE;
        event["path"] = utf8_from_wide(info->path);
        hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
        log_event("close", std::move(event));
    }

    SetLastError(last_error);
    return ok;
}

BOOL WINAPI DeleteFileW_detour(LPCWSTR path) {
    BOOL ok = g_orig_DeleteFileW(path);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["path"] = utf8_from_wide(widen(path));
    event["success"] = ok != FALSE;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("delete", std::move(event));

    SetLastError(last_error);
    return ok;
}

BOOL WINAPI MoveFileExW_detour(LPCWSTR existing, LPCWSTR target, DWORD flags) {
    BOOL ok = g_orig_MoveFileExW(existing, target, flags);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["from"] = utf8_from_wide(widen(existing));
    event["to"] = utf8_from_wide(widen(target));
    event["flags"] = flags;
    event["success"] = ok != FALSE;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("move", std::move(event));

    SetLastError(last_error);
    return ok;
}

DWORD WINAPI GetFileAttributesW_detour(LPCWSTR path) {
    DWORD result = g_orig_GetFileAttributesW(path);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["path"] = utf8_from_wide(widen(path));
    bool success = result != INVALID_FILE_ATTRIBUTES;
    event["success"] = success;
    if (success) {
        event["attributes"] = result;
    } else {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("get_attributes", std::move(event));
    SetLastError(last_error);
    return result;
}

BOOL WINAPI GetFileAttributesExW_detour(LPCWSTR path,
                                        GET_FILEEX_INFO_LEVELS level,
                                        LPVOID data) {
    BOOL ok = g_orig_GetFileAttributesExW(path, level, data);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["path"] = utf8_from_wide(widen(path));
    event["level"] = static_cast<int>(level);
    event["success"] = ok != FALSE;
    if (!ok) {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("get_attributes_ex", std::move(event));
    SetLastError(last_error);
    return ok;
}

DWORD WINAPI GetModuleFileNameW_detour(HMODULE module, LPWSTR filename, DWORD size) {
    DWORD result = g_orig_GetModuleFileNameW(module, filename, size);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["module"] = reinterpret_cast<std::uintptr_t>(module);
    event["size"] = size;
    event["result_length"] = result;
    event["success"] = result != 0;
    if (result > 0 && filename) {
        event["path"] = utf8_from_wide(std::wstring(filename, result));
    }
    if (result == 0) {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("get_module_filename", std::move(event));
    SetLastError(last_error);
    return result;
}

HANDLE WINAPI FindFirstFileW_detour(LPCWSTR pattern, LPWIN32_FIND_DATAW data) {
    HANDLE handle = g_orig_FindFirstFileW(pattern, data);
    DWORD last_error = GetLastError();

    if (handle != INVALID_HANDLE_VALUE) {
        store_find_info(handle, FindHandleInfo{widen(pattern)});
    }

    nlohmann::json event;
    event["pattern"] = utf8_from_wide(widen(pattern));
    event["success"] = handle != INVALID_HANDLE_VALUE;
    if (handle != INVALID_HANDLE_VALUE && data != nullptr) {
        event["match"] = utf8_from_wide(data->cFileName);
    } else if (handle == INVALID_HANDLE_VALUE) {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("find_first", std::move(event));
    SetLastError(last_error);
    return handle;
}

BOOL WINAPI FindNextFileW_detour(HANDLE handle, LPWIN32_FIND_DATAW data) {
    BOOL ok = g_orig_FindNextFileW(handle, data);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["handle"] = reinterpret_cast<std::uintptr_t>(handle);
    if (auto info = lookup_find_info(handle)) {
        event["pattern"] = utf8_from_wide(info->pattern);
    }
    event["success"] = ok != FALSE;
    if (ok && data != nullptr) {
        event["match"] = utf8_from_wide(data->cFileName);
    } else if (!ok) {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("find_next", std::move(event));
    SetLastError(last_error);
    return ok;
}

BOOL WINAPI FindClose_detour(HANDLE handle) {
    BOOL ok = g_orig_FindClose(handle);
    DWORD last_error = GetLastError();

    nlohmann::json event;
    event["handle"] = reinterpret_cast<std::uintptr_t>(handle);
    if (auto info = lookup_find_info(handle)) {
        event["pattern"] = utf8_from_wide(info->pattern);
    }
    event["success"] = ok != FALSE;
    if (!ok) {
        event["error"] = last_error;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("find_close", std::move(event));
    erase_find_info(handle);
    SetLastError(last_error);
    return ok;
}

LSTATUS WINAPI RegOpenKeyExW_detour(HKEY key, LPCWSTR sub_key, DWORD options, REGSAM desired,
                                    PHKEY result) {
    LSTATUS status = g_orig_RegOpenKeyExW(key, sub_key, options, desired, result);

    if (status == ERROR_SUCCESS && result) {
        store_reg_info(*result, combine_key_path(key, sub_key ? std::wstring_view(sub_key) : std::wstring_view()));
    }

    nlohmann::json event;
    event["parent"] = utf8_from_wide(describe_hkey(key));
    event["sub_key"] = utf8_from_wide(widen(sub_key));
    event["success"] = status == ERROR_SUCCESS;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.open", std::move(event));
    return status;
}

LSTATUS WINAPI RegCreateKeyExW_detour(HKEY key, LPCWSTR sub_key, DWORD reserved, LPWSTR lpClass,
                                      DWORD options, REGSAM samDesired,
                                      LPSECURITY_ATTRIBUTES security, PHKEY result,
                                      LPDWORD disposition) {
    LSTATUS status = g_orig_RegCreateKeyExW(key, sub_key, reserved, lpClass, options, samDesired,
                                            security, result, disposition);

    if (status == ERROR_SUCCESS && result) {
        store_reg_info(*result, combine_key_path(key, sub_key ? std::wstring_view(sub_key) : std::wstring_view()));
    }

    nlohmann::json event;
    event["parent"] = utf8_from_wide(describe_hkey(key));
    event["sub_key"] = utf8_from_wide(widen(sub_key));
    event["success"] = status == ERROR_SUCCESS;
    if (disposition) {
        event["disposition"] = *disposition;
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.create", std::move(event));
    return status;
}

std::string preview_registry_value(DWORD type, const BYTE* data, DWORD size) {
    if (!data || size == 0) {
        return {};
    }
    switch (type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
        case REG_MULTI_SZ: {
            std::size_t wchar_count = size / sizeof(wchar_t);
            if (wchar_count == 0) {
                return {};
            }
            std::wstring wide(reinterpret_cast<const wchar_t*>(data),
                              reinterpret_cast<const wchar_t*>(data) + wchar_count);
            if (type == REG_MULTI_SZ) {
                for (auto& ch : wide) {
                    if (ch == L'\0') {
                        ch = L'\n';
                    }
                }
            }
            return utf8_from_wide(wide);
        }
        default:
            return preview_buffer(data, size);
    }
}

LSTATUS WINAPI RegSetValueExW_detour(HKEY key, LPCWSTR value_name, DWORD reserved, DWORD type,
                                     const BYTE* data, DWORD data_size) {
    LSTATUS status = g_orig_RegSetValueExW(key, value_name, reserved, type, data, data_size);

    nlohmann::json event;
    event["key"] = utf8_from_wide(describe_hkey(key));
    event["value_name"] = utf8_from_wide(widen(value_name));
    event["type"] = type;
    event["data_size"] = data_size;
    event["success"] = status == ERROR_SUCCESS;
    if (data && data_size > 0) {
        event["payload_preview"] = preview_registry_value(type, data, data_size);
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.set", std::move(event));
    return status;
}

LSTATUS WINAPI RegQueryValueExW_detour(HKEY key, LPCWSTR value_name, LPDWORD reserved,
                                       LPDWORD type, LPBYTE data, LPDWORD data_size) {
    LSTATUS status = g_orig_RegQueryValueExW(key, value_name, reserved, type, data, data_size);

    nlohmann::json event;
    event["key"] = utf8_from_wide(describe_hkey(key));
    event["value_name"] = utf8_from_wide(widen(value_name));
    event["success"] = status == ERROR_SUCCESS;
    if (type && data_size) {
        event["type"] = *type;
        event["data_size"] = *data_size;
    }
    if (status == ERROR_SUCCESS && data && data_size && *data_size > 0 && type) {
        event["payload_preview"] = preview_registry_value(*type, data, *data_size);
    }
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.query", std::move(event));
    return status;
}

LSTATUS WINAPI RegDeleteKeyW_detour(HKEY key, LPCWSTR sub_key) {
    LSTATUS status = g_orig_RegDeleteKeyW(key, sub_key);

    nlohmann::json event;
    event["parent"] = utf8_from_wide(describe_hkey(key));
    event["sub_key"] = utf8_from_wide(widen(sub_key));
    event["success"] = status == ERROR_SUCCESS;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.delete_key", std::move(event));
    return status;
}

LSTATUS WINAPI RegDeleteValueW_detour(HKEY key, LPCWSTR value_name) {
    LSTATUS status = g_orig_RegDeleteValueW(key, value_name);

    nlohmann::json event;
    event["key"] = utf8_from_wide(describe_hkey(key));
    event["value_name"] = utf8_from_wide(widen(value_name));
    event["success"] = status == ERROR_SUCCESS;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.delete_value", std::move(event));
    return status;
}

LSTATUS WINAPI RegCloseKey_detour(HKEY key) {
    LSTATUS status = g_orig_RegCloseKey(key);
    if (status == ERROR_SUCCESS) {
        erase_reg_info(key);
    }
    nlohmann::json event;
    event["key"] = utf8_from_wide(describe_hkey(key));
    event["success"] = status == ERROR_SUCCESS;
    hooks::append_caller(event, hooks::resolve_caller(EXL_RETURN_ADDRESS()));
    log_event("reg.close", std::move(event));
    return status;
}

}  // namespace

bool FileMonHook::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED) {
        return false;
    }
    g_instance = this;

    bool ok = true;
    ok &= hook_api(L"kernel32.dll", "CreateFileW", &CreateFileW_detour, &g_orig_CreateFileW);
    ok &= hook_api(L"kernel32.dll", "ReadFile", &ReadFile_detour, &g_orig_ReadFile);
    ok &= hook_api(L"kernel32.dll", "WriteFile", &WriteFile_detour, &g_orig_WriteFile);
    ok &= hook_api(L"kernel32.dll", "CloseHandle", &CloseHandle_detour, &g_orig_CloseHandle);
    ok &= hook_api(L"kernel32.dll", "DeleteFileW", &DeleteFileW_detour, &g_orig_DeleteFileW);
    ok &= hook_api(L"kernel32.dll", "MoveFileExW", &MoveFileExW_detour, &g_orig_MoveFileExW);
    ok &= hook_api(L"kernel32.dll", "GetFileAttributesW", &GetFileAttributesW_detour, &g_orig_GetFileAttributesW);
    ok &= hook_api(L"kernel32.dll", "GetFileAttributesExW", &GetFileAttributesExW_detour, &g_orig_GetFileAttributesExW);
    ok &= hook_api(L"kernel32.dll", "GetModuleFileNameW", &GetModuleFileNameW_detour, &g_orig_GetModuleFileNameW);
    ok &= hook_api(L"kernel32.dll", "FindFirstFileW", &FindFirstFileW_detour, &g_orig_FindFirstFileW);
    ok &= hook_api(L"kernel32.dll", "FindNextFileW", &FindNextFileW_detour, &g_orig_FindNextFileW);
    ok &= hook_api(L"kernel32.dll", "FindClose", &FindClose_detour, &g_orig_FindClose);

    ok &= hook_api(L"advapi32.dll", "RegOpenKeyExW", &RegOpenKeyExW_detour, &g_orig_RegOpenKeyExW);
    ok &= hook_api(L"advapi32.dll", "RegCreateKeyExW", &RegCreateKeyExW_detour, &g_orig_RegCreateKeyExW);
    ok &= hook_api(L"advapi32.dll", "RegSetValueExW", &RegSetValueExW_detour, &g_orig_RegSetValueExW);
    ok &= hook_api(L"advapi32.dll", "RegQueryValueExW", &RegQueryValueExW_detour, &g_orig_RegQueryValueExW);
    ok &= hook_api(L"advapi32.dll", "RegDeleteKeyW", &RegDeleteKeyW_detour, &g_orig_RegDeleteKeyW);
    ok &= hook_api(L"advapi32.dll", "RegDeleteValueW", &RegDeleteValueW_detour, &g_orig_RegDeleteValueW);
    ok &= hook_api(L"advapi32.dll", "RegCloseKey", &RegCloseKey_detour, &g_orig_RegCloseKey);

    hooks_installed_ = ok;
    if (!hooks_installed_) {
        shutdown();
    }
    return hooks_installed_;
}

void FileMonHook::shutdown() {
    if (hooks_installed_) {
        for (void* target : g_hook_targets) {
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
        g_hook_targets.clear();
    }
    {
        std::lock_guard lock(g_file_mutex);
        g_file_handles.clear();
    }
    {
        std::lock_guard lock(g_reg_mutex);
        g_reg_handles.clear();
    }
    {
        std::lock_guard lock(g_find_mutex);
        g_find_handles.clear();
    }
    g_instance = nullptr;
    context_ = nullptr;
    hooks_installed_ = false;
}

}  // namespace exloader::runtime::hooks::modules

#else

namespace exloader::runtime::hooks::modules {

bool FileMonHook::initialize(const PluginContext&) { return false; }
void FileMonHook::shutdown() {}

}  // namespace exloader::runtime::hooks::modules

#endif
