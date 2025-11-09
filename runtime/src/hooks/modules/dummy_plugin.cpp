#include "exloader/runtime/hooks/modules/dummy_plugin.hpp"

#include <nlohmann/json.hpp>

#include "exloader/logging/json_logger.hpp"

namespace exloader::runtime::hooks::modules {

bool DummyPlugin::initialize(const PluginContext& ctx) {
    context_ = &ctx;
    if (context_->logger) {
        context_->logger->log({
            {"type", "plugin.start"},
            {"plugin", std::string(name())}
        });
    }
    return true;
}

void DummyPlugin::shutdown() {
    if (context_ && context_->logger) {
        context_->logger->log({
            {"type", "plugin.stop"},
            {"plugin", std::string(name())}
        });
    }
}

}  // namespace exloader::runtime::hooks::modules
