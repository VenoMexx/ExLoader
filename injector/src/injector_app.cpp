#include "exloader/injector/injector_app.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#endif

#include "exloader/config/config_loader.hpp"
#include "exloader/injector/process_launcher.hpp"
#include "exloader/runtime/bootstrap.hpp"

namespace {

#if defined(_WIN32)
std::wstring utf8_to_wide_local(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), len);
    return wide;
}
#endif

void tail_log_file(const std::filesystem::path& path) {
    if (path.empty()) {
        std::cout << "[follow] stdout logging already enabled\n";
        return;
    }

    std::ifstream stream;
    for (int attempts = 0; attempts < 40; ++attempts) {
        stream.open(path);
        if (stream) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    if (!stream) {
        std::cerr << "[follow] unable to open log after waiting: " << path << '\n';
        return;
    }
    stream.seekg(0, std::ios::end);

    std::string line;
    while (true) {
        while (std::getline(stream, line)) {
            std::cout << line << '\n';
        }
        if (!stream.eof()) {
            std::cerr << "[follow] log read error\n";
            break;
        }
        stream.clear();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

template <std::size_t N>
void copy_cstr(char (&dest)[N], const std::string& value, const char* field_name) {
    if (value.size() >= N) {
        throw std::runtime_error(std::string(field_name) + " exceeds the maximum length (" +
                                 std::to_string(N - 1) + ")");
    }
    std::memset(dest, 0, N);
    std::memcpy(dest, value.data(), value.size());
}

}  // namespace

namespace exloader::injector {

void InjectorApp::print_plan(const config::ProfileConfig& profile, bool attach_mode) {
    std::cout << "Profile: " << profile.name << '\n';
    std::cout << "Target: "
              << (profile.target.launch.empty() ? "<attach-only>" : profile.target.launch.string())
              << '\n';
    std::cout << "Log file: "
              << (profile.logging.path.empty() ? "<stdout>" : profile.logging.path.string())
              << '\n';
    std::cout << "Mode: " << (attach_mode ? "PID attach" : "launch") << '\n';
}

int InjectorApp::run(const cli::Options& options) {
    try {
        config::ConfigLoader loader;
        config::ProfileConfig profile =
            loader.load(options.profile, options.target_override, options.log_override,
                        options.target_args, options.workdir_override);

        const bool attach_mode = options.attach || options.pid.has_value();
        if (!attach_mode && profile.target.launch.empty()) {
            throw std::runtime_error("Launch mode requires target.launch or --target override.");
        }

        if (!profile.logging.path.empty()) {
            profile.logging.path = std::filesystem::absolute(profile.logging.path);
        }

        runtime::bootstrap::BootstrapConfig bootstrap{};
        copy_cstr(bootstrap.profile_name, profile.name, "profile.name");
        if (!profile.logging.path.empty()) {
            const std::u8string log_path_u8 = profile.logging.path.generic_u8string();
            std::string log_path_utf8(log_path_u8.begin(), log_path_u8.end());
            copy_cstr(bootstrap.log_path, log_path_utf8, "logging.path");
        }
        bootstrap.log_stdout = profile.logging.stdout_enabled;
        bootstrap.max_log_bytes = profile.logging.max_bytes_per_entry;

        std::vector<std::pair<std::string, bool>> module_summary;
        module_summary.reserve(profile.modules.size());
        for (const auto& module : profile.modules) {
            const bool enabled = module.enabled && (!attach_mode || module.allow_in_attach);
            if (bootstrap.module_count >= runtime::bootstrap::kMaxModules) {
                throw std::runtime_error("Profile references more than " +
                                         std::to_string(runtime::bootstrap::kMaxModules) +
                                         " modules.");
            }
            copy_cstr(bootstrap.modules[bootstrap.module_count].name, module.name, "module.name");
            bootstrap.modules[bootstrap.module_count].enabled = enabled;
            ++bootstrap.module_count;
            module_summary.emplace_back(module.name, enabled);
        }

        print_plan(profile, attach_mode);
        std::cout << "\nRuntime summary:\n";
        if (module_summary.empty()) {
            std::cout << "  <no modules requested>\n";
        } else {
            for (const auto& entry : module_summary) {
                std::cout << "  - " << entry.first << " : "
                          << (entry.second ? "enabled" : "disabled") << '\n';
            }
        }

        if (options.validate_only) {
            return 0;
        }

#if defined(_WIN32)
        ProcessLauncher launcher;
        std::string launcher_error;
        bool launcher_ready = true;
        const bool resolved_attach = attach_mode || options.pid.has_value();

        if (resolved_attach) {
            if (!options.pid.has_value()) {
                launcher_ready = false;
                std::cerr << "[injector] PID attach requires --pid.\n";
            } else if (!launcher.attach(static_cast<unsigned long>(*options.pid), launcher_error)) {
                launcher_ready = false;
                std::cerr << "[injector] Attach failed: " << launcher_error << '\n';
            }
        } else {
            std::filesystem::path exe_path = profile.target.launch;
            if (exe_path.empty()) {
                launcher_ready = false;
                std::cerr << "[injector] Launch path missing.\n";
            } else {
                exe_path = std::filesystem::absolute(exe_path);
                if (!std::filesystem::exists(exe_path)) {
                    launcher_ready = false;
                    std::cerr << "[injector] Target executable not found: " << exe_path << '\n';
                }
                LaunchConfig launch_cfg{};
                launch_cfg.executable = exe_path.wstring();
                launch_cfg.arguments = utf8_to_wide_local(profile.target.arguments);
                if (!profile.target.working_directory.empty()) {
                    launch_cfg.working_directory = profile.target.working_directory.wstring();
                } else if (!exe_path.parent_path().empty()) {
                    launch_cfg.working_directory = exe_path.parent_path().wstring();
                }
                if (!launcher.launch(launch_cfg, launcher_error)) {
                    launcher_ready = false;
                    std::cerr << "[injector] Launch failed: " << launcher_error << '\n';
                } else {
                    std::cout << "[injector] Launched PID " << launcher.target_pid() << '\n';
                }
            }
        }

        if (launcher_ready) {
            std::filesystem::path dll_path;
            if (!options.dll_override.empty()) {
                dll_path = options.dll_override;
            } else {
                // Auto-detect DLL path: look in the same directory as exloader.exe
                wchar_t exe_path_buf[MAX_PATH];
                GetModuleFileNameW(nullptr, exe_path_buf, MAX_PATH);
                std::filesystem::path exe_dir = std::filesystem::path(exe_path_buf).parent_path();
                dll_path = exe_dir / "libexadapter_core.dll";
            }
            dll_path = std::filesystem::absolute(dll_path);
            if (!std::filesystem::exists(dll_path)) {
                std::cerr << "[injector] Runtime DLL missing: " << dll_path << '\n';
                launcher_ready = false;
            } else {
                InjectionMethod method = parse_injection_method(options.injection_method);
                InjectionConfig inj_cfg{};
                inj_cfg.dll_path = dll_path.wstring();
                inj_cfg.method = method;
                if (!launcher.inject(inj_cfg, launcher_error)) {
                    std::cerr << "[injector] Injection failed (" << injection_method_name(method)
                              << "): " << launcher_error << '\n';
                    launcher_ready = false;
                } else if (!launcher.initialize_runtime(bootstrap, dll_path.wstring(),
                                                         launcher_error)) {
                    std::cerr << "[injector] Runtime initialization failed: " << launcher_error
                              << '\n';
                    launcher_ready = false;
                } else {
                    std::cout << "[injector] Runtime bootstrap completed.\n";
                }
            }
            launcher.resume_if_needed();
        }
#else
        std::cerr << "Process injection only supported on Windows.\n";
#endif

        if (options.follow_logs) {
            tail_log_file(profile.logging.path);
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
}

}  // namespace exloader::injector
