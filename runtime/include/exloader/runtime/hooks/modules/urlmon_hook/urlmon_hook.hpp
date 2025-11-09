#pragma once

#include "exloader/runtime/hooks/plugin_api.hpp"

namespace exloader::runtime::hooks::modules {

class UrlmonHook : public IPlugin {
public:
    std::string_view name() const override { return "network.urlmon"; }
    std::string_view version() const override { return "0.1.0"; }

    bool initialize(const PluginContext& ctx) override;
    void shutdown() override;

    const PluginContext* context() const { return context_; }

private:
    bool install_hooks();
    void uninstall_hooks();

    const PluginContext* context_{nullptr};
    bool hooks_installed_{false};
};

}  // namespace exloader::runtime::hooks::modules
