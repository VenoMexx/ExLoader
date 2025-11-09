#pragma once

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "exloader/runtime/hooks/plugin_api.hpp"

namespace exloader::runtime {

namespace hooks {
class PluginManager;
}

struct ModuleDescriptor {
    std::string name;
    std::string version;
    bool enabled{true};
};

struct RuntimeOptions {
    std::string profile_name;
    std::vector<ModuleDescriptor> requested_modules;
    std::string control_pipe_name;
    std::vector<std::string> enabled_hooks;
    logging::JsonLogger* logger{nullptr};
    std::size_t max_payload_bytes{4096};
};

class Runtime {
public:
    Runtime();
    ~Runtime();

    void configure(RuntimeOptions options);
    [[nodiscard]] std::string summary() const;

private:
    RuntimeOptions options_{};
    std::unique_ptr<hooks::PluginManager> plugin_manager_;
};

}  // namespace exloader::runtime
