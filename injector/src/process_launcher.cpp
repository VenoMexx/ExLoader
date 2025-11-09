#include "exloader/injector/process_launcher.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <TlHelp32.h>
#include <processthreadsapi.h>
#include <psapi.h>

#include <filesystem>
#include <cwctype>
#include <cstdint>
#include <system_error>
#include <vector>

namespace exloader::injector {

namespace {

std::wstring utf8_to_wide(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, wide.data(), len);
    return wide;
}

std::wstring quote_command(const std::wstring& exe, const std::wstring& args) {
    std::wstring cmd = L"\"" + exe + L"\"";
    if (!args.empty()) {
        cmd.push_back(L' ');
        cmd += args;
    }
    return cmd;
}

std::wstring path_to_wstring(const std::filesystem::path& path) {
    return path.wstring();
}

std::wstring to_lower(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return value;
}

}  // namespace

ProcessLauncher::ProcessLauncher() = default;

ProcessLauncher::~ProcessLauncher() {
    if (primary_thread_) {
        CloseHandle(primary_thread_);
    }
    if (process_handle_) {
        CloseHandle(process_handle_);
    }
}

bool ProcessLauncher::launch(const LaunchConfig& config, std::string& error) {
    last_injected_module_ = nullptr;
    if (primary_thread_) {
        CloseHandle(primary_thread_);
        primary_thread_ = nullptr;
    }
    if (process_handle_) {
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
    }
    if (config.executable.empty()) {
        error = "Executable path is empty.";
        return false;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    std::wstring cmd = quote_command(config.executable, config.arguments);
    std::vector<wchar_t> cmd_buffer(cmd.begin(), cmd.end());
    cmd_buffer.push_back(L'\0');

    std::wstring workdir = config.working_directory.empty() ? L"" : config.working_directory;
    LPWSTR cmd_ptr = cmd_buffer.empty() ? nullptr : cmd_buffer.data();

    if (!CreateProcessW(config.executable.c_str(), cmd_ptr, nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, workdir.empty() ? nullptr : workdir.c_str(), &si,
                        &pi)) {
        error = "CreateProcessW failed with error " + std::to_string(GetLastError());
        return false;
    }

    process_handle_ = pi.hProcess;
    primary_thread_ = pi.hThread;
    target_pid_ = pi.dwProcessId;
    created_process_ = true;
    return true;
}

bool ProcessLauncher::attach(unsigned long pid, std::string& error) {
    last_injected_module_ = nullptr;
    if (primary_thread_) {
        CloseHandle(primary_thread_);
        primary_thread_ = nullptr;
    }
    if (process_handle_) {
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
    }
    HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                                     PROCESS_VM_WRITE | PROCESS_VM_READ,
                                FALSE, pid);
    if (!process) {
        error = "OpenProcess failed with error " + std::to_string(GetLastError());
        return false;
    }
    if (!verify_architecture(process, error)) {
        CloseHandle(process);
        return false;
    }
    process_handle_ = process;
    target_pid_ = pid;
    created_process_ = false;
    return true;
}

void ProcessLauncher::resume_if_needed() {
    if (created_process_ && primary_thread_) {
        ResumeThread(primary_thread_);
    }
}

bool ProcessLauncher::inject(const InjectionConfig& config, std::string& error) {
    if (process_handle_ == nullptr) {
        error = "Process handle is not initialized.";
        return false;
    }
    switch (config.method) {
        case InjectionMethod::RemoteThread:
            return inject_via_remote_thread(config.dll_path, error);
        case InjectionMethod::QueueApc:
            return inject_via_apc(config.dll_path, error);
    }
    error = "Unsupported injection method.";
    return false;
}

bool ProcessLauncher::verify_architecture(HANDLE process, std::string& error) {
    BOOL self_wow64 = FALSE;
    BOOL target_wow64 = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &self_wow64)) {
        error = "IsWow64Process failed on current process.";
        return false;
    }
    if (!IsWow64Process(process, &target_wow64)) {
        error = "IsWow64Process failed on target.";
        return false;
    }
    if (self_wow64 != target_wow64) {
        error = "Injector/target architecture mismatch.";
        return false;
    }
    return true;
}

bool ProcessLauncher::inject_via_remote_thread(const std::wstring& dll_path, std::string& error) {
    if (dll_path.empty()) {
        error = "DLL path cannot be empty.";
        return false;
    }
    const SIZE_T size = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(process_handle_, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        error = "VirtualAllocEx failed with error " + std::to_string(GetLastError());
        return false;
    }
    if (!WriteProcessMemory(process_handle_, remote, dll_path.c_str(), size, nullptr)) {
        error = "WriteProcessMemory failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!kernel32) {
        error = "GetModuleHandleW(kernel32) failed.";
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        return false;
    }
    auto load_library =
        reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
    if (!load_library) {
        error = "GetProcAddress(LoadLibraryW) failed.";
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process_handle_, nullptr, 0, load_library, remote, 0, nullptr);
    if (!thread) {
        error = "CreateRemoteThread failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        return false;
    }
    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code = 0;
    if (!GetExitCodeThread(thread, &exit_code) || exit_code == 0) {
        error = "LoadLibraryW returned NULL (dependency or architecture mismatch).";
        last_injected_module_ = nullptr;
        CloseHandle(thread);
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        return false;
    }
    last_injected_module_ = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(exit_code));
    CloseHandle(thread);
    VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
    return true;
}

HANDLE ProcessLauncher::pick_thread_for_apc(unsigned long pid) {
    if (primary_thread_) {
        return primary_thread_;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    HANDLE thread_handle = nullptr;

    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid) {
                thread_handle = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                           FALSE, entry.th32ThreadID);
                if (thread_handle) {
                    break;
                }
            }
        } while (Thread32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return thread_handle;
}

bool ProcessLauncher::inject_via_apc(const std::wstring& dll_path, std::string& error) {
    HANDLE thread = pick_thread_for_apc(target_pid_);
    if (!thread) {
        error = "No suitable thread found for APC injection.";
        return false;
    }

    const SIZE_T size = (dll_path.size() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(process_handle_, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        error = "VirtualAllocEx failed with error " + std::to_string(GetLastError());
        if (thread != primary_thread_) {
            CloseHandle(thread);
        }
        return false;
    }
    if (!WriteProcessMemory(process_handle_, remote, dll_path.c_str(), size, nullptr)) {
        error = "WriteProcessMemory failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        if (thread != primary_thread_) {
            CloseHandle(thread);
        }
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    auto load_library =
        reinterpret_cast<PAPCFUNC>(GetProcAddress(kernel32, "LoadLibraryW"));
    if (!load_library) {
        error = "GetProcAddress(LoadLibraryW) failed.";
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        if (thread != primary_thread_) {
            CloseHandle(thread);
        }
        return false;
    }

    DWORD suspend_count = SuspendThread(thread);
    if (suspend_count == static_cast<DWORD>(-1)) {
        error = "SuspendThread failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        if (thread != primary_thread_) {
            CloseHandle(thread);
        }
        return false;
    }

    if (QueueUserAPC(load_library, thread, reinterpret_cast<ULONG_PTR>(remote)) == 0) {
        error = "QueueUserAPC failed with error " + std::to_string(GetLastError());
        ResumeThread(thread);
        VirtualFreeEx(process_handle_, remote, 0, MEM_RELEASE);
        if (thread != primary_thread_) {
            CloseHandle(thread);
        }
        return false;
    }

    ResumeThread(thread);
    if (thread != primary_thread_) {
        CloseHandle(thread);
    }
    last_injected_module_ = nullptr;
    return true;
}

bool ProcessLauncher::initialize_runtime(const runtime::bootstrap::BootstrapConfig& config,
                                         const std::wstring& dll_path,
                                         std::string& error) {
    if (!process_handle_) {
        error = "Process handle is invalid.";
        return false;
    }

    const SIZE_T size = sizeof(config);
    LPVOID remote_config = VirtualAllocEx(process_handle_, nullptr, size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_config) {
        error = "VirtualAllocEx (bootstrap) failed with error " + std::to_string(GetLastError());
        return false;
    }

    if (!WriteProcessMemory(process_handle_, remote_config, &config, size, nullptr)) {
        error = "WriteProcessMemory (bootstrap) failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote_config, 0, MEM_RELEASE);
        return false;
    }

    HMODULE remote_module = last_injected_module_;
    if (!remote_module) {
        remote_module = find_remote_module(dll_path, error);
    } else {
        error.clear();
    }
    if (!remote_module) {
        VirtualFreeEx(process_handle_, remote_config, 0, MEM_RELEASE);
        return false;
    }

    LPVOID entry = resolve_remote_procedure(remote_module, dll_path, "ExLoaderRuntimeBootstrap", error);
    if (!entry) {
        VirtualFreeEx(process_handle_, remote_config, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process_handle_, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(entry),
                                       remote_config, 0, nullptr);
    if (!thread) {
        error = "CreateRemoteThread (bootstrap) failed with error " + std::to_string(GetLastError());
        VirtualFreeEx(process_handle_, remote_config, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code = ERROR_GEN_FAILURE;
    if (!GetExitCodeThread(thread, &exit_code)) {
        exit_code = ERROR_GEN_FAILURE;
    }
    CloseHandle(thread);
    VirtualFreeEx(process_handle_, remote_config, 0, MEM_RELEASE);

    if (exit_code != ERROR_SUCCESS) {
        error = "Runtime bootstrap failed with code " + std::to_string(exit_code);
        return false;
    }
    return true;
}

HMODULE ProcessLauncher::find_remote_module(const std::wstring& dll_path, std::string& error) {
    std::error_code ec;
    std::wstring target_full = to_lower(std::filesystem::weakly_canonical(dll_path, ec).wstring());
    if (target_full.empty()) {
        target_full = to_lower(std::filesystem::absolute(dll_path).wstring());
    }
    const std::wstring target_name = to_lower(std::filesystem::path(dll_path).filename().wstring());
    constexpr int kMaxAttempts = 100;

    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        DWORD bytes_needed = 0;
        if (!EnumProcessModulesEx(process_handle_, nullptr, 0, &bytes_needed, LIST_MODULES_ALL)) {
            error = "EnumProcessModulesEx failed with error " + std::to_string(GetLastError());
            return nullptr;
        }

        std::vector<HMODULE> modules(bytes_needed / sizeof(HMODULE));
        if (!EnumProcessModulesEx(process_handle_, modules.data(),
                                  static_cast<DWORD>(modules.size() * sizeof(HMODULE)),
                                  &bytes_needed, LIST_MODULES_ALL)) {
            error = "EnumProcessModulesEx failed with error " + std::to_string(GetLastError());
            return nullptr;
        }

        for (HMODULE module : modules) {
            wchar_t path_buffer[MAX_PATH];
            if (GetModuleFileNameExW(process_handle_, module, path_buffer,
                                     static_cast<DWORD>(sizeof(path_buffer) / sizeof(wchar_t))) == 0) {
                continue;
            }
            const std::wstring candidate_full = to_lower(std::wstring(path_buffer));
            const std::wstring candidate_name =
                to_lower(std::filesystem::path(path_buffer).filename().wstring());
            if ((!target_full.empty() && candidate_full == target_full) ||
                candidate_name == target_name) {
                return module;
            }
        }
        Sleep(50);
    }

    error = "Injected module not found in target process.";
    return nullptr;
}

LPVOID ProcessLauncher::resolve_remote_procedure(HMODULE remote_module,
                                                 const std::wstring& dll_path,
                                                 LPCSTR proc_name,
                                                 std::string& error) {
    HMODULE local_module = LoadLibraryExW(dll_path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!local_module) {
        error = "LoadLibraryEx failed for " + std::string(proc_name);
        return nullptr;
    }

    std::vector<std::string> candidates;
    candidates.emplace_back(proc_name);
#if INTPTR_MAX == INT32_MAX
    candidates.emplace_back(std::string(proc_name) + "@4");
    candidates.emplace_back(std::string("_") + proc_name + "@4");
#endif

    FARPROC local_proc = nullptr;
    for (const auto& candidate : candidates) {
        local_proc = GetProcAddress(local_module, candidate.c_str());
        if (local_proc != nullptr) {
            break;
        }
    }
    if (!local_proc) {
        error = "GetProcAddress failed for " + std::string(proc_name);
        FreeLibrary(local_module);
        return nullptr;
    }

    const auto local_base = reinterpret_cast<std::uintptr_t>(local_module);
    const auto remote_base = reinterpret_cast<std::uintptr_t>(remote_module);
    const auto offset = reinterpret_cast<std::uintptr_t>(local_proc) - local_base;
    LPVOID remote_proc = reinterpret_cast<LPVOID>(remote_base + offset);
    FreeLibrary(local_module);
    return remote_proc;
}

}  // namespace exloader::injector

#else

namespace exloader::injector {

// Stub implementations handled in header.

}  // namespace exloader::injector

#endif

namespace exloader::injector {

InjectionMethod parse_injection_method(std::string_view method) {
    std::string lowered(method.begin(), method.end());
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "apc" || lowered == "apc-queue" || lowered == "queue-apc") {
        return InjectionMethod::QueueApc;
    }
    return InjectionMethod::RemoteThread;
}

std::string_view injection_method_name(InjectionMethod method) {
    switch (method) {
        case InjectionMethod::RemoteThread:
            return "remote-thread";
        case InjectionMethod::QueueApc:
            return "queue-apc";
    }
    return "unknown";
}

}  // namespace exloader::injector
