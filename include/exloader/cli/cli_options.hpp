#pragma once

#include <filesystem>
#include <string>
#include <optional>

namespace exloader::cli {

struct Options {
    std::filesystem::path profile;
    std::filesystem::path target_override;
    std::filesystem::path log_override;
    bool attach{false};
    std::string target_args;
    std::filesystem::path workdir_override;
    std::filesystem::path dll_override;
    std::optional<unsigned long> pid;
    std::string injection_method{"remote-thread"};
    bool follow_logs{false};
    bool validate_only{false};
};

}  // namespace exloader::cli
