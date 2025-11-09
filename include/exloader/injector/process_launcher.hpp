#pragma once

#include <string>
#include <string_view>

#if defined(_WIN32)
#include <windows.h>
#endif

#include <filesystem>

#include "exloader/runtime/bootstrap.hpp"

namespace exloader::injector {

enum class InjectionMethod {
    RemoteThread,
    QueueApc,
};

#if defined(_WIN32)

struct LaunchConfig {
    std::wstring executable;
    std::wstring arguments;
    std::wstring working_directory;
};

struct InjectionConfig {
    std::wstring dll_path;
    InjectionMethod method{InjectionMethod::RemoteThread};
};

class ProcessLauncher {
public:
    ProcessLauncher();
    ~ProcessLauncher();

    bool launch(const LaunchConfig& config, std::string& error);
    bool attach(unsigned long pid, std::string& error);
    bool inject(const InjectionConfig& config, std::string& error);
    bool initialize_runtime(const runtime::bootstrap::BootstrapConfig& config,
                            const std::wstring& dll_path,
                            std::string& error);
    void resume_if_needed();
    unsigned long target_pid() const { return target_pid_; }
    std::wstring utf8_to_wide(const std::string& input) const;

private:
    bool verify_architecture(HANDLE process, std::string& error);
    bool inject_via_remote_thread(const std::wstring& dll_path, std::string& error);
    bool inject_via_apc(const std::wstring& dll_path, std::string& error);
    HANDLE pick_thread_for_apc(unsigned long pid);
    HMODULE find_remote_module(const std::wstring& dll_path, std::string& error);
    LPVOID resolve_remote_procedure(HMODULE remote_module,
                                    const std::wstring& dll_path,
                                    LPCSTR proc_name,
                                    std::string& error);

    HANDLE process_handle_{nullptr};
    HANDLE primary_thread_{nullptr};
    unsigned long target_pid_{0};
    bool created_process_{false};
    HMODULE last_injected_module_{nullptr};
};

#else

struct LaunchConfig {
    std::wstring executable;
    std::wstring arguments;
    std::wstring working_directory;
};

struct InjectionConfig {
    std::wstring dll_path;
    InjectionMethod method{InjectionMethod::RemoteThread};
};

class ProcessLauncher {
public:
    bool launch(const LaunchConfig&, std::string& error) {
        error = "Process launching is only supported on Windows.";
        return false;
    }
    bool attach(unsigned long, std::string& error) {
        error = "Attach is only supported on Windows.";
        return false;
    }
    bool inject(const InjectionConfig&, std::string& error) {
        error = "Injection is only supported on Windows.";
        return false;
    }
    bool initialize_runtime(const runtime::bootstrap::BootstrapConfig&,
                            const std::wstring&,
                            std::string& error) {
        error = "Runtime initialization is only supported on Windows.";
        return false;
    }
    void resume_if_needed() {}
    unsigned long target_pid() const { return 0; }
};

#endif

InjectionMethod parse_injection_method(std::string_view method);
std::string_view injection_method_name(InjectionMethod method);

}  // namespace exloader::injector
