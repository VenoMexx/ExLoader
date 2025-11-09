#include "http_server.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")

namespace test_target {

namespace {

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

std::vector<std::string> split(const std::string& str, const std::string& delim) {
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = str.find(delim);
    while (end != std::string::npos) {
        result.push_back(str.substr(start, end - start));
        start = end + delim.length();
        end = str.find(delim, start);
    }
    result.push_back(str.substr(start));
    return result;
}

}  // namespace

SimpleHttpServer::SimpleHttpServer(int port)
    : port_(port), running_(false) {}

SimpleHttpServer::~SimpleHttpServer() {
    stop();
}

void SimpleHttpServer::add_handler(const std::string& path, HttpHandler handler) {
    handlers_[path] = handler;
}

bool SimpleHttpServer::start() {
    if (running_) return false;

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return false;
    }

    running_ = true;
    server_thread_ = std::thread([this]() { server_thread(); });
    return true;
}

void SimpleHttpServer::stop() {
    if (!running_) return;
    running_ = false;
    if (server_thread_.joinable()) {
        server_thread_.join();
    }
    WSACleanup();
}

void SimpleHttpServer::server_thread() {
    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        running_ = false;
        return;
    }

    // Set socket to non-blocking for clean shutdown
    u_long mode = 1;
    ioctlsocket(listen_socket, FIONBIO, &mode);

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_addr.sin_port = htons(static_cast<u_short>(port_));

    if (bind(listen_socket, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(listen_socket);
        running_ = false;
        return;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listen_socket);
        running_ = false;
        return;
    }

    while (running_) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_socket, &read_fds);

        timeval timeout{};
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;  // 100ms

        int select_result = select(0, &read_fds, nullptr, nullptr, &timeout);
        if (select_result <= 0) continue;

        SOCKET client_socket = accept(listen_socket, nullptr, nullptr);
        if (client_socket == INVALID_SOCKET) continue;

        // Set client socket to blocking
        mode = 0;
        ioctlsocket(client_socket, FIONBIO, &mode);

        // Read request - need to keep reading until we have the complete request
        std::string raw_request;
        char buffer[8192];
        bool headers_complete = false;
        size_t content_length = 0;
        size_t body_start = 0;

        // First, read until we get all headers (look for \r\n\r\n)
        while (!headers_complete) {
            int received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            if (received <= 0) break;

            buffer[received] = '\0';
            raw_request.append(buffer, received);

            // Check if headers are complete
            size_t header_end = raw_request.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                headers_complete = true;
                body_start = header_end + 4;

                // Parse Content-Length from headers
                size_t cl_pos = raw_request.find("Content-Length:");
                if (cl_pos != std::string::npos && cl_pos < header_end) {
                    size_t cl_start = cl_pos + 15; // strlen("Content-Length:")
                    size_t cl_end = raw_request.find("\r\n", cl_start);
                    if (cl_end != std::string::npos) {
                        std::string cl_str = trim(raw_request.substr(cl_start, cl_end - cl_start));
                        content_length = std::stoul(cl_str);
                    }
                }
            }
        }

        // Now read the body if Content-Length was specified
        if (headers_complete && content_length > 0) {
            size_t current_body_size = raw_request.size() - body_start;
            while (current_body_size < content_length) {
                int received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
                if (received <= 0) break;

                buffer[received] = '\0';
                raw_request.append(buffer, received);
                current_body_size = raw_request.size() - body_start;
            }
        }

        if (headers_complete) {
            ServerHttpRequest request = parse_request(raw_request);
            ServerHttpResponse response = handle_request(request);
            std::string response_str = build_response(response);

            send(client_socket, response_str.c_str(), static_cast<int>(response_str.length()), 0);
        }

        closesocket(client_socket);
    }

    closesocket(listen_socket);
}

ServerHttpRequest SimpleHttpServer::parse_request(const std::string& raw_request) {
    ServerHttpRequest request;

    auto lines = split(raw_request, "\r\n");
    if (lines.empty()) return request;

    // Parse request line: "POST /path HTTP/1.1"
    auto request_line_parts = split(lines[0], " ");
    if (request_line_parts.size() >= 2) {
        request.method = request_line_parts[0];
        request.path = request_line_parts[1];
    }

    // Parse headers
    size_t i = 1;
    for (; i < lines.size(); ++i) {
        if (lines[i].empty()) {
            ++i;
            break;
        }
        size_t colon_pos = lines[i].find(':');
        if (colon_pos != std::string::npos) {
            std::string key = trim(lines[i].substr(0, colon_pos));
            std::string value = trim(lines[i].substr(colon_pos + 1));
            request.headers[key] = value;
        }
    }

    // Parse body
    if (i < lines.size()) {
        std::ostringstream body_stream;
        for (; i < lines.size(); ++i) {
            body_stream << lines[i];
            if (i + 1 < lines.size()) body_stream << "\r\n";
        }
        request.body = body_stream.str();
    }

    return request;
}

ServerHttpResponse SimpleHttpServer::handle_request(const ServerHttpRequest& request) {
    auto it = handlers_.find(request.path);
    if (it != handlers_.end()) {
        return it->second(request);
    }

    ServerHttpResponse response;
    response.status_code = 404;
    response.status_text = "Not Found";
    response.body = "{\"error\":\"Not Found\"}";
    response.headers["Content-Type"] = "application/json";
    return response;
}

std::string SimpleHttpServer::build_response(const ServerHttpResponse& response) {
    std::ostringstream stream;
    stream << "HTTP/1.1 " << response.status_code << " " << response.status_text << "\r\n";

    for (const auto& header : response.headers) {
        stream << header.first << ": " << header.second << "\r\n";
    }

    stream << "Content-Length: " << response.body.length() << "\r\n";
    stream << "Connection: close\r\n";
    stream << "\r\n";
    stream << response.body;

    return stream.str();
}

}  // namespace test_target
