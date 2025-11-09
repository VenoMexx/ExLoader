#include "exloader/config/config_loader.hpp"

#include <cstdint>
#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "exloader/config/config_types.hpp"

namespace exloader::config {

namespace {

bool is_truthy(const nlohmann::json& value, bool default_value) {
    return value.is_boolean() ? value.get<bool>() : default_value;
}

std::size_t clamp_size(const nlohmann::json& value, std::size_t fallback) {
    if (!value.is_number_unsigned()) {
        return fallback;
    }
    return static_cast<std::size_t>(value.get<std::uint64_t>());
}

}  // namespace

void ConfigLoader::validate_json(const nlohmann::json& data) {
    if (!data.is_object()) {
        throw std::runtime_error("Profile JSON must be an object");
    }
    if (!data.contains("name") || !data["name"].is_string()) {
        throw std::runtime_error("'name' field is required and must be a string");
    }
    if (!data.contains("logging") || !data["logging"].is_object()) {
        throw std::runtime_error("'logging' object is required");
    }
    if (!data.contains("target") || !data["target"].is_object()) {
        throw std::runtime_error("'target' object is required");
    }
    if (!data.contains("modules") || !data["modules"].is_array() || data["modules"].empty()) {
        throw std::runtime_error("'modules' array is required and cannot be empty");
    }
}

std::vector<ModuleDefinition> ConfigLoader::parse_modules(const nlohmann::json& data) {
    std::vector<ModuleDefinition> modules;
    modules.reserve(data.size());

    for (const auto& entry : data) {
        ModuleDefinition def{};
        if (entry.is_string()) {
            def.name = entry.get<std::string>();
        } else if (entry.is_object()) {
            if (!entry.contains("name") || !entry["name"].is_string()) {
                throw std::runtime_error("Module object must contain a string 'name' field");
            }
            def.name = entry["name"].get<std::string>();
            if (entry.contains("enabled")) {
                def.enabled = entry["enabled"].get<bool>();
            }
            if (entry.contains("allow_in_attach")) {
                def.allow_in_attach = entry["allow_in_attach"].get<bool>();
            }
        } else {
            throw std::runtime_error("Module entry must be a string or object");
        }

        if (def.name.empty()) {
            throw std::runtime_error("Module name cannot be empty");
        }
        modules.push_back(def);
    }

    return modules;
}

ProfileConfig ConfigLoader::load(const std::filesystem::path& path,
                                 const std::filesystem::path& target_override,
                                 const std::filesystem::path& log_override,
                                 const std::string& args_override,
                                 const std::filesystem::path& workdir_override) const {
    std::ifstream stream(path);
    if (!stream) {
        throw std::runtime_error("Profile file cannot be opened: " + path.string());
    }

    const auto data = nlohmann::json::parse(stream, nullptr, true, true);
    validate_json(data);

    ProfileConfig config{};
    config.name = data["name"].get<std::string>();
    config.modules = parse_modules(data["modules"]);

    const auto& logging = data["logging"];
    if (logging.contains("path") && logging["path"].is_string()) {
        config.logging.path = logging["path"].get<std::string>();
    }
    config.logging.stdout_enabled = is_truthy(logging.value("stdout", true), true);
    config.logging.max_bytes_per_entry =
        clamp_size(logging.value("max_bytes_per_entry", config.logging.max_bytes_per_entry),
                   config.logging.max_bytes_per_entry);

    const auto& target = data["target"];
    if (target.contains("launch") && target["launch"].is_string()) {
        config.target.launch = target["launch"].get<std::string>();
    }
    if (target.contains("arguments") && target["arguments"].is_string()) {
        config.target.arguments = target["arguments"].get<std::string>();
    }
    if (target.contains("working_directory") && target["working_directory"].is_string()) {
        config.target.working_directory = target["working_directory"].get<std::string>();
    }

    if (!target_override.empty()) {
        config.target.launch = target_override;
    }
    if (!log_override.empty()) {
        config.logging.path = log_override;
    }
    if (!args_override.empty()) {
        config.target.arguments = args_override;
    }
    if (!workdir_override.empty()) {
        config.target.working_directory = workdir_override;
    }

    return config;
}

ConfigLoader::ValidationResult ConfigLoader::validate(const std::filesystem::path& path) const {
    ValidationResult result{};
    std::ifstream stream(path);
    if (!stream) {
        result.errors.emplace_back("Profile file cannot be opened: " + path.string());
        return result;
    }

    const auto data = nlohmann::json::parse(stream, nullptr, true, true);
    try {
        validate_json(data);
    } catch (const std::exception& ex) {
        result.errors.emplace_back(ex.what());
        return result;
    }

    ProfileConfig profile = load(path);
    result.ok = true;
    result.modules.reserve(profile.modules.size());
    for (const auto& module : profile.modules) {
        if (module.enabled) {
            result.modules.push_back(module.name);
        }
    }
    result.max_payload_bytes = profile.logging.max_bytes_per_entry;
    result.target_path = profile.target.launch;
    result.log_path = profile.logging.path;
    return result;
}

}  // namespace exloader::config
