#pragma once

#include <string>
#include <functional>
#include <map>
#include <thread>
#include <atomic>

namespace test_target {

struct ServerHttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::map<std::string, std::string> headers;
};

struct ServerHttpResponse {
    int status_code;
    std::string status_text;
    std::string body;
    std::map<std::string, std::string> headers;

    ServerHttpResponse() : status_code(200), status_text("OK") {}
};

using HttpHandler = std::function<ServerHttpResponse(const ServerHttpRequest&)>;

class SimpleHttpServer {
public:
    SimpleHttpServer(int port = 5432);
    ~SimpleHttpServer();

    void add_handler(const std::string& path, HttpHandler handler);
    bool start();
    void stop();
    bool is_running() const { return running_; }

private:
    void server_thread();
    ServerHttpResponse handle_request(const ServerHttpRequest& request);
    ServerHttpRequest parse_request(const std::string& raw_request);
    std::string build_response(const ServerHttpResponse& response);

    int port_;
    std::atomic<bool> running_;
    std::thread server_thread_;
    std::map<std::string, HttpHandler> handlers_;
};

}  // namespace test_target
