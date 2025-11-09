#pragma once

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace exloader::config {

struct LoggingConfig {
    std::filesystem::path path;
    bool stdout_enabled{true};
    std::size_t max_bytes_per_entry{32768};
};

struct TargetConfig {
    std::filesystem::path launch;
    std::string arguments;
    std::filesystem::path working_directory;
};

struct ModuleDefinition {
    std::string name;
    bool enabled{true};
    bool allow_in_attach{true};
};

struct ProfileConfig {
    std::string name;
    LoggingConfig logging;
    TargetConfig target;
    std::vector<ModuleDefinition> modules;
};

struct RuntimeLaunchPlan {
    ProfileConfig profile;
    bool attach_mode{false};
};

}  // namespace exloader::config
