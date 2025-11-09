#include "exloader/runtime/hooks/plugin_manager.hpp"

#include <algorithm>
#include <iostream>

namespace exloader::runtime::hooks {

PluginManager::PluginManager() = default;

void PluginManager::set_context(PluginContext ctx) {
    context_ = ctx;
}

void PluginManager::register_plugin(PluginPtr plugin) {
    if (plugin) {
        plugins_.push_back(std::move(plugin));
    }
}

void PluginManager::activate_enabled(const std::vector<std::string>& enabled_modules) {
    for (auto& plugin : plugins_) {
        const bool should_enable = std::find(enabled_modules.begin(), enabled_modules.end(),
                                             plugin->name()) != enabled_modules.end();
        if (!should_enable) {
            continue;
        }

        try {
            if (!plugin->initialize(context_)) {
                std::cerr << "Plugin failed to initialize: " << plugin->name() << "\n";
            }
        } catch (const std::exception& ex) {
            std::cerr << "Plugin exception during initialize: " << plugin->name() << " - "
                      << ex.what() << "\n";
        }
    }
}

void PluginManager::shutdown() {
    for (auto& plugin : plugins_) {
        try {
            plugin->shutdown();
        } catch (const std::exception& ex) {
            std::cerr << "Plugin exception during shutdown: " << plugin->name() << " - "
                      << ex.what() << "\n";
        }
    }
    plugins_.clear();
}

}  // namespace exloader::runtime::hooks
