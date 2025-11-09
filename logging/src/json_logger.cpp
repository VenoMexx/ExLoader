#include "exloader/logging/json_logger.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <ctime>

#if defined(_WIN32)
#include <windows.h>
#else
#include <chrono>
#endif

#include <nlohmann/json.hpp>

namespace exloader::logging {

namespace {

std::unique_ptr<std::ofstream> open_stream(const std::filesystem::path& path) {
    if (path.empty()) {
        return nullptr;
    }

    std::error_code ec;
    if (!path.parent_path().empty()) {
        std::filesystem::create_directories(path.parent_path(), ec);
    }

    auto stream = std::make_unique<std::ofstream>(path, std::ios::app);
    if (!*stream) {
        throw std::runtime_error("Log dosyası açılamadı: " + path.string());
    }
    return stream;
}

}  // namespace

JsonLogger::JsonLogger(std::filesystem::path path,
                       bool mirror_stdout,
                       std::size_t max_bytes_per_entry)
    : path_(std::move(path)),
      mirror_stdout_(mirror_stdout),
      max_bytes_(max_bytes_per_entry) {
    stream_ = open_stream(path_);
}

std::string JsonLogger::iso8601_now() {
#if defined(_WIN32)
    SYSTEMTIME st{};
    GetSystemTime(&st);
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << st.wYear << '-' << std::setw(2) << st.wMonth << '-'
        << std::setw(2) << st.wDay << 'T' << std::setw(2) << st.wHour << ':' << std::setw(2)
        << st.wMinute << ':' << std::setw(2) << st.wSecond << '.' << std::setw(3)
        << st.wMilliseconds << 'Z';
    return oss.str();
#else
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
    const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();

    std::time_t time = clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&time, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0')
        << millis << 'Z';
    return oss.str();
#endif
}

std::string JsonLogger::encode_entry(nlohmann::json& message) const {
    if (!message.contains("ts")) {
        message["ts"] = iso8601_now();
    }

    std::string serialized = message.dump();
    if (max_bytes_ != 0 && serialized.size() > max_bytes_) {
        nlohmann::json truncated{
            {"ts", message["ts"]},
            {"type", "logger.truncate"},
            {"original_type", message.value("type", "unknown")},
            {"max_bytes", max_bytes_}
        };
        serialized = truncated.dump();
    }

    serialized.push_back('\n');
    return serialized;
}

void JsonLogger::write_line(const std::string& line) {
    if (stream_) {
        (*stream_) << line;
        stream_->flush();
    }

    if (mirror_stdout_) {
        std::cout << line;
    }
}

void JsonLogger::log(nlohmann::json message) {
    const std::string line = encode_entry(message);
    std::lock_guard<std::mutex> lock(mutex_);
    write_line(line);
}

}  // namespace exloader::logging
