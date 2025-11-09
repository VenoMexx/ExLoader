#pragma once

#include <filesystem>
#include <string>

#include <nlohmann/json_fwd.hpp>

#include "exloader/config/config_types.hpp"

namespace exloader::config {

class ConfigLoader {
public:
    ProfileConfig load(const std::filesystem::path& path,
                      const std::filesystem::path& target_override = {},
                      const std::filesystem::path& log_override = {},
                      const std::string& args_override = {},
                      const std::filesystem::path& workdir_override = {}) const;

    struct ValidationResult {
        bool ok{false};
        std::vector<std::string> errors;
        std::vector<std::string> modules;
        std::size_t max_payload_bytes{0};
        std::filesystem::path target_path;
        std::filesystem::path log_path;
    };

    ValidationResult validate(const std::filesystem::path& path) const;

private:
    static void validate_json(const nlohmann::json& data);
    static std::vector<ModuleDefinition> parse_modules(const nlohmann::json& data);
};

}  // namespace exloader::config
