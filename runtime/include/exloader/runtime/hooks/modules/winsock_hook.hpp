#pragma once

#include "exloader/runtime/hooks/plugin_api.hpp"

namespace exloader::runtime::hooks::modules {

class WinSockHook : public IPlugin {
public:
    std::string_view name() const override { return "network.winsock"; }
    std::string_view version() const override { return "0.1.0"; }

    bool initialize(const PluginContext& ctx) override;
    void shutdown() override;

    const PluginContext* context() const { return context_; }

private:
    bool hooks_installed_{false};
    const PluginContext* context_{nullptr};
};

}  // namespace exloader::runtime::hooks::modules
