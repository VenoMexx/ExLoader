#pragma once

#include <memory>
#include <string>
#include <vector>

#include "exloader/runtime/hooks/plugin_api.hpp"

namespace exloader::runtime::hooks {

class PluginManager {
public:
    PluginManager();

    void set_context(PluginContext ctx);
    void register_plugin(PluginPtr plugin);
    void activate_enabled(const std::vector<std::string>& enabled_modules);

    void shutdown();

private:
    PluginContext context_{};
    std::vector<PluginPtr> plugins_;
};

}  // namespace exloader::runtime::hooks
