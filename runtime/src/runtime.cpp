#include "exloader/runtime/runtime_api.hpp"

#include <chrono>
#include <sstream>

#if defined(_WIN32)
#include "exloader/ipc/named_pipe.hpp"
#endif

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"
#include "exloader/runtime/hooks/plugin_manager.hpp"
#include "exloader/runtime/hooks/modules/dummy_plugin.hpp"
#include "exloader/runtime/hooks/modules/winhttp_hook.hpp"
#include "exloader/runtime/hooks/modules/winhttp_extended/winhttp_extended_hook.hpp"
#include "exloader/runtime/hooks/modules/urlmon_hook/urlmon_hook.hpp"
#include "exloader/runtime/hooks/modules/win32web_hook/win32web_hook.hpp"
#include "exloader/runtime/hooks/modules/proxy_hook/proxy_hook.hpp"
#include "exloader/runtime/hooks/modules/libcurl_hook/libcurl_hook.hpp"
#include "exloader/runtime/hooks/modules/http_sys_hook/http_sys_hook.hpp"
#include "exloader/runtime/hooks/modules/wininet_hook.hpp"
#include "exloader/runtime/hooks/modules/winsock_hook.hpp"
#include "exloader/runtime/hooks/modules/stringmon_hook.hpp"
#include "exloader/runtime/hooks/modules/mathmon_hook.hpp"
#include "exloader/runtime/hooks/modules/filemon_hook.hpp"
#include "exloader/runtime/hooks/modules/bcrypt_hook.hpp"
#include "exloader/runtime/hooks/modules/cryptoapi_hook.hpp"
#include "exloader/runtime/hooks/modules/schannel_hook/schannel_hook.hpp"
#include "exloader/runtime/hooks/modules/urlmon_hook/urlmon_hook.hpp"

namespace exloader::runtime {

Runtime::Runtime() = default;
Runtime::~Runtime() {
    if (plugin_manager_) {
        plugin_manager_->shutdown();
    }
}

void Runtime::configure(RuntimeOptions options) {
    options_ = std::move(options);
    if (plugin_manager_) {
        plugin_manager_->shutdown();
    }

#if defined(_WIN32)
    if (!options_.control_pipe_name.empty()) {
        ipc::NamedPipeClient client(options_.control_pipe_name);
        if (client.connect(std::chrono::milliseconds(500))) {
            std::string heartbeat = R"({"type":"runtime.heartbeat","status":"ready"})";
            heartbeat.push_back('\n');
            client.send(heartbeat);
        }
    }
#endif

    plugin_manager_ = std::make_unique<hooks::PluginManager>();

    auto log_plugin_register = [this](const char* name) {
        if (options_.logger) {
        nlohmann::json summary;
        summary["type"] = "plugin.register";
        summary["plugin"] = name;
        options_.logger->log(std::move(summary));
        }
    };

    log_plugin_register("dummy");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::DummyPlugin>());

    log_plugin_register("winhttp");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::WinHttpHook>());

    log_plugin_register("winhttp.extended");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::WinHttpExtendedHook>());

    log_plugin_register("urlmon");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::UrlmonHook>());

    log_plugin_register("win32web");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::Win32WebHook>());

    log_plugin_register("proxy");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::ProxyHook>());

    log_plugin_register("libcurl");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::LibcurlHook>());

    log_plugin_register("http_sys");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::HttpSysHook>());

    log_plugin_register("schannel");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::SchannelHook>());

    log_plugin_register("wininet");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::WinInetHook>());

    log_plugin_register("winsock");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::WinSockHook>());

    log_plugin_register("stringmon");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::StringMonHook>());

    log_plugin_register("mathmon");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::MathMonHook>());

    log_plugin_register("filesystem.filemon");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::FileMonHook>());

    log_plugin_register("bcrypt");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::BCryptHook>());

    log_plugin_register("cryptoapi");
    plugin_manager_->register_plugin(std::make_unique<hooks::modules::CryptoApiHook>());

    if (options_.logger) {
        nlohmann::json msg;
        msg["type"] = "plugin.register";
        msg["status"] = "all_registered";
        options_.logger->log(std::move(msg));
    }

    hooks::PluginContext ctx{};
    ctx.logger = options_.logger;
    ctx.profile_name = options_.profile_name;
    ctx.max_payload_bytes = options_.max_payload_bytes;
    plugin_manager_->set_context(ctx);

    if (options_.logger) {
        nlohmann::json msg;
        msg["type"] = "plugin.activate";
        msg["status"] = "starting";
        options_.logger->log(std::move(msg));
    }

    plugin_manager_->activate_enabled(options_.enabled_hooks);

    if (options_.logger) {
        nlohmann::json msg;
        msg["type"] = "plugin.activate";
        msg["status"] = "completed";
        options_.logger->log(std::move(msg));
    }
}

std::string Runtime::summary() const {
    std::ostringstream stream;
    stream << "Profile: " << (options_.profile_name.empty() ? "<none>" : options_.profile_name)
           << "\n";
    stream << "Modules:\n";
    for (const auto& module : options_.requested_modules) {
        stream << "  - " << module.name << " (" << module.version << ") : "
               << (module.enabled ? "enabled" : "disabled") << "\n";
    }

    if (options_.requested_modules.empty()) {
        stream << "  <no modules requested>\n";
    }

    return stream.str();
}

}  // namespace exloader::runtime
