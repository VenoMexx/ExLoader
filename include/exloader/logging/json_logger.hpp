#pragma once

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace exloader::logging {

class JsonLogger {
public:
    JsonLogger(std::filesystem::path path,
               bool mirror_stdout,
               std::size_t max_bytes_per_entry);

    void log(nlohmann::json message);

private:
    static std::string iso8601_now();
    std::string encode_entry(nlohmann::json& message) const;
    void write_line(const std::string& line);

    std::filesystem::path path_;
    bool mirror_stdout_{true};
    std::size_t max_bytes_{0};

    mutable std::mutex mutex_;
    std::unique_ptr<std::ofstream> stream_;
};

}  // namespace exloader::logging
