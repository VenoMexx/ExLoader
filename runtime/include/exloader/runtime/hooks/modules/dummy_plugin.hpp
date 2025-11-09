#pragma once

#include "exloader/runtime/hooks/plugin_api.hpp"

namespace exloader::runtime::hooks::modules {

class DummyPlugin : public IPlugin {
public:
    std::string_view name() const override { return "dummy.plugin"; }
    std::string_view version() const override { return "0.1.0"; }

    bool initialize(const PluginContext& ctx) override;
    void shutdown() override;

private:
    const PluginContext* context_{nullptr};
};

}  // namespace exloader::runtime::hooks::modules
