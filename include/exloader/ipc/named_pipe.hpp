#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace exloader::ipc {

class NamedPipeServer {
public:
    using MessageHandler = std::function<void(std::string_view)>;

    explicit NamedPipeServer(std::string pipe_name);
    ~NamedPipeServer();

    NamedPipeServer(const NamedPipeServer&) = delete;
    NamedPipeServer& operator=(const NamedPipeServer&) = delete;

    void start(MessageHandler handler);
    void stop();

    [[nodiscard]] const std::string& pipe_name() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class NamedPipeClient {
public:
    explicit NamedPipeClient(std::string pipe_name);
    ~NamedPipeClient();

    NamedPipeClient(const NamedPipeClient&) = delete;
    NamedPipeClient& operator=(const NamedPipeClient&) = delete;

    bool connect(std::chrono::milliseconds timeout);
    bool send(std::string_view payload);
    void close();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace exloader::ipc
