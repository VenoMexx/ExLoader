#include "exloader/ipc/named_pipe.hpp"

#include <atomic>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace exloader::ipc {

namespace {

std::string sanitize_name(std::string name) {
    if (name.empty()) {
        return "\\\\.\\pipe\\exloader_default";
    }
    return name;
}

}  // namespace

#if defined(_WIN32)

#include <windows.h>

namespace {

std::wstring widen(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (needed <= 0) {
        throw std::runtime_error("Failed to convert pipe name to wide char");
    }
    std::wstring buffer(static_cast<std::size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, buffer.data(), needed);
    return buffer;
}

}  // namespace

struct NamedPipeServer::Impl {
    explicit Impl(std::string pipe_name)
        : pipe_name_(sanitize_name(std::move(pipe_name))) {}

    void start(MessageHandler handler) {
        stop();
        handler_ = std::move(handler);
        stop_requested_.store(false);
        worker_ = std::thread([this]() { this->worker_loop(); });
    }

    void stop() {
        stop_requested_.store(true);
        if (pipe_handle_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(pipe_handle_, nullptr);
            DisconnectNamedPipe(pipe_handle_);
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    const std::string& pipe_name() const { return pipe_name_; }

private:
    void worker_loop() {
        const std::wstring wide_name = widen(pipe_name_);
        while (!stop_requested_.load()) {
            pipe_handle_ = CreateNamedPipeW(wide_name.c_str(),
                                            PIPE_ACCESS_DUPLEX,
                                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                            1,
                                            4096,
                                            4096,
                                            0,
                                            nullptr);
            if (pipe_handle_ == INVALID_HANDLE_VALUE) {
                break;
            }

            const BOOL connected = ConnectNamedPipe(pipe_handle_, nullptr)
                                        ? TRUE
                                        : (GetLastError() == ERROR_PIPE_CONNECTED);
            if (!connected) {
                CloseHandle(pipe_handle_);
                pipe_handle_ = INVALID_HANDLE_VALUE;
                continue;
            }

            std::string buffer;
            buffer.reserve(512);
            while (!stop_requested_.load()) {
                char chunk[512];
                DWORD bytes_read = 0;
                const BOOL read_ok = ReadFile(pipe_handle_, chunk, sizeof(chunk), &bytes_read, nullptr);
                if (!read_ok || bytes_read == 0) {
                    break;
                }
                buffer.append(chunk, bytes_read);
                std::size_t newline_pos = 0;
                while ((newline_pos = buffer.find('\n')) != std::string::npos) {
                    const std::string line = buffer.substr(0, newline_pos);
                    buffer.erase(0, newline_pos + 1);
                    MessageHandler handler_copy;
                    {
                        std::lock_guard<std::mutex> lock(handler_mutex_);
                        handler_copy = handler_;
                    }
                    if (handler_copy) {
                        handler_copy(line);
                    }
                }
            }

            FlushFileBuffers(pipe_handle_);
            DisconnectNamedPipe(pipe_handle_);
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }
    }

    std::string pipe_name_{};
    HANDLE pipe_handle_{INVALID_HANDLE_VALUE};
    std::thread worker_{};
    std::mutex handler_mutex_{};
    MessageHandler handler_{};
    std::atomic<bool> stop_requested_{false};
};

struct NamedPipeClient::Impl {
    explicit Impl(std::string pipe_name)
        : pipe_name_(sanitize_name(std::move(pipe_name))) {}

    bool connect(std::chrono::milliseconds timeout) {
        const std::wstring wide_name = widen(pipe_name_);
        while (true) {
            pipe_handle_ = CreateFileW(wide_name.c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       0,
                                       nullptr);
            if (pipe_handle_ != INVALID_HANDLE_VALUE) {
                DWORD mode = PIPE_READMODE_MESSAGE;
                SetNamedPipeHandleState(pipe_handle_, &mode, nullptr, nullptr);
                return true;
            }

            if (GetLastError() != ERROR_PIPE_BUSY) {
                return false;
            }

            const DWORD wait_time = timeout.count() <= 0
                                        ? NMPWAIT_USE_DEFAULT_WAIT
                                        : static_cast<DWORD>(timeout.count());
            if (!WaitNamedPipeW(wide_name.c_str(), wait_time)) {
                return false;
            }
        }
    }

    bool send(std::string_view payload) {
        if (pipe_handle_ == INVALID_HANDLE_VALUE) {
            return false;
        }
        DWORD bytes_written = 0;
        const BOOL ok = WriteFile(pipe_handle_, payload.data(), static_cast<DWORD>(payload.size()),
                                  &bytes_written, nullptr);
        return ok && bytes_written == payload.size();
    }

    void close() {
        if (pipe_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_handle_);
            pipe_handle_ = INVALID_HANDLE_VALUE;
        }
    }

    ~Impl() { close(); }

private:
    std::string pipe_name_{};
    HANDLE pipe_handle_{INVALID_HANDLE_VALUE};
};

NamedPipeServer::NamedPipeServer(std::string pipe_name)
    : impl_(std::make_unique<Impl>(std::move(pipe_name))) {}

NamedPipeServer::~NamedPipeServer() { stop(); }

void NamedPipeServer::start(MessageHandler handler) {
    impl_->start(std::move(handler));
}

void NamedPipeServer::stop() {
    if (impl_) {
        impl_->stop();
    }
}

const std::string& NamedPipeServer::pipe_name() const {
    return impl_->pipe_name();
}

NamedPipeClient::NamedPipeClient(std::string pipe_name)
    : impl_(std::make_unique<Impl>(std::move(pipe_name))) {}

NamedPipeClient::~NamedPipeClient() = default;

bool NamedPipeClient::connect(std::chrono::milliseconds timeout) {
    return impl_->connect(timeout);
}

bool NamedPipeClient::send(std::string_view payload) {
    return impl_->send(payload);
}

void NamedPipeClient::close() {
    impl_->close();
}

#else  // Non-Windows stubs

struct NamedPipeServer::Impl {
    explicit Impl(std::string pipe_name) : pipe_name_(std::move(pipe_name)) {}
    void start(MessageHandler) {}
    void stop() {}
    const std::string& pipe_name() const { return pipe_name_; }
    std::string pipe_name_{};
};

struct NamedPipeClient::Impl {
    explicit Impl(std::string pipe_name) : pipe_name_(std::move(pipe_name)) {}
    bool connect(std::chrono::milliseconds) { return false; }
    bool send(std::string_view) { return false; }
    void close() {}
    std::string pipe_name_{};
};

NamedPipeServer::NamedPipeServer(std::string pipe_name)
    : impl_(std::make_unique<Impl>(std::move(pipe_name))) {}

NamedPipeServer::~NamedPipeServer() = default;

void NamedPipeServer::start(MessageHandler handler) {
    (void)handler;
}

void NamedPipeServer::stop() {}

const std::string& NamedPipeServer::pipe_name() const {
    return impl_->pipe_name();
}

NamedPipeClient::NamedPipeClient(std::string pipe_name)
    : impl_(std::make_unique<Impl>(std::move(pipe_name))) {}

NamedPipeClient::~NamedPipeClient() = default;

bool NamedPipeClient::connect(std::chrono::milliseconds) {
    return false;
}

bool NamedPipeClient::send(std::string_view) {
    return false;
}

void NamedPipeClient::close() {}

#endif

}  // namespace exloader::ipc
