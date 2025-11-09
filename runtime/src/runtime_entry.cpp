#include "exloader/runtime/bootstrap.hpp"

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/runtime_api.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#error "Runtime bootstrap is only supported on Windows builds."
#endif

namespace {

std::unique_ptr<exloader::runtime::Runtime> g_runtime;
std::unique_ptr<exloader::logging::JsonLogger> g_logger;
std::once_flag g_runtime_once;

std::filesystem::path path_from_utf8(const char* value) {
    if (value == nullptr || *value == '\0') {
        return {};
    }
    return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(value)));
}

void log_runtime_start(const exloader::runtime::bootstrap::BootstrapConfig& config) {
    if (!g_logger) {
        return;
    }
    nlohmann::json modules = nlohmann::json::array();
    for (std::uint32_t i = 0; i < config.module_count && i < exloader::runtime::bootstrap::kMaxModules;
         ++i) {
        modules.push_back({
            {"name", std::string(config.modules[i].name)},
            {"enabled", config.modules[i].enabled}
        });
    }
    g_logger->log({
        {"type", "runtime.start"},
        {"profile", std::string(config.profile_name)},
        {"log_path", std::string(config.log_path)},
        {"modules", modules}
    });
}

}  // namespace

namespace {

DWORD bootstrap_impl(const exloader::runtime::bootstrap::BootstrapConfig* config) {
    if (config == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    try {
        std::call_once(g_runtime_once, []() {
            g_runtime = std::make_unique<exloader::runtime::Runtime>();
        });
        if (!g_runtime) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        auto logger = std::make_unique<exloader::logging::JsonLogger>(
            path_from_utf8(config->log_path),
            config->log_stdout,
            config->max_log_bytes);

        logger->log({
            {"type", "runtime.bootstrap"},
            {"status", "starting"},
            {"profile", std::string(config->profile_name)}
        });

        exloader::runtime::RuntimeOptions options{};
        options.profile_name = std::string(config->profile_name);
        options.logger = logger.get();
        options.max_payload_bytes = config->max_log_bytes;
        options.control_pipe_name = std::string(config->control_pipe);
        options.requested_modules.reserve(config->module_count);
        options.enabled_hooks.reserve(config->module_count);

        for (std::uint32_t i = 0;
             i < config->module_count && i < exloader::runtime::bootstrap::kMaxModules;
             ++i) {
            exloader::runtime::ModuleDescriptor desc{};
            desc.name = std::string(config->modules[i].name);
            desc.version = "0.1.0";
            desc.enabled = config->modules[i].enabled;
            options.requested_modules.push_back(desc);
            if (desc.enabled) {
                options.enabled_hooks.push_back(desc.name);
            }
        }

        logger->log({
            {"type", "runtime.bootstrap"},
            {"status", "configuring"},
            {"module_count", config->module_count}
        });

        g_runtime->configure(std::move(options));

        g_logger = std::move(logger);
        log_runtime_start(*config);

        g_logger->log({
            {"type", "runtime.bootstrap"},
            {"status", "success"}
        });
        return ERROR_SUCCESS;
    } catch (const std::exception& ex) {
        char buf[512];
        snprintf(buf, sizeof(buf), "C++ Exception: %s", ex.what());
        MessageBoxA(NULL, buf, "Bootstrap Exception", MB_OK | MB_ICONERROR);
        if (g_logger) {
            g_logger->log({
                {"type", "runtime.bootstrap"},
                {"status", "error"},
                {"error", ex.what()}
            });
        }
        return ERROR_GEN_FAILURE;
    } catch (...) {
        MessageBoxA(NULL, "Unknown C++ exception", "Bootstrap Exception", MB_OK | MB_ICONERROR);
        if (g_logger) {
            g_logger->log({
                {"type", "runtime.bootstrap"},
                {"status", "error"},
                {"error", "unknown exception"}
            });
        }
        return ERROR_GEN_FAILURE;
    }
}

}  // namespace

extern "C" __declspec(dllexport) DWORD WINAPI ExLoaderRuntimeBootstrap(
    const exloader::runtime::bootstrap::BootstrapConfig* config) {
    return bootstrap_impl(config);
}
