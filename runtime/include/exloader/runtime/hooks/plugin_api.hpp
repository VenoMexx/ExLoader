#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace exloader::logging {
class JsonLogger;
}

namespace exloader::runtime::hooks {

inline constexpr std::string_view kPluginApiVersion = "0.1.0";

enum class EventType : std::uint32_t {
    kUnknown = 0,
    kNetworkRequest,
    kNetworkResponse,
    kCryptoEncrypt,
    kCryptoDecrypt,
    kCryptoKey,
};

struct Event {
    EventType type{EventType::kUnknown};
    std::string payload;
};

struct PluginContext {
    logging::JsonLogger* logger{nullptr};
    std::string_view profile_name;
    std::size_t max_payload_bytes{4096};
};

class IPlugin {
public:
    virtual ~IPlugin() = default;

    virtual std::string_view name() const = 0;
    virtual std::string_view version() const = 0;

    virtual bool initialize(const PluginContext& ctx) = 0;
    virtual void shutdown() = 0;
};

using PluginPtr = std::unique_ptr<IPlugin>;

}  // namespace exloader::runtime::hooks
