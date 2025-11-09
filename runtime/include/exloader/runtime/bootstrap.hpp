#pragma once

#include <cstddef>
#include <cstdint>

namespace exloader::runtime::bootstrap {

constexpr std::size_t kMaxProfileNameLength = 64;
constexpr std::size_t kMaxPathLength = 520;
constexpr std::size_t kMaxModuleNameLength = 64;
constexpr std::size_t kMaxModules = 32;

struct ModuleConfig {
    char name[kMaxModuleNameLength]{};
    bool enabled{false};
    std::uint8_t reserved[7]{};
};

struct BootstrapConfig {
    char profile_name[kMaxProfileNameLength]{};
    char log_path[kMaxPathLength]{};
    bool log_stdout{true};
    std::uint8_t padding[7]{};
    std::size_t max_log_bytes{32768};
    char control_pipe[kMaxPathLength]{};
    std::uint32_t module_count{0};
    std::uint32_t reserved{0};
    ModuleConfig modules[kMaxModules]{};
};

}  // namespace exloader::runtime::bootstrap
