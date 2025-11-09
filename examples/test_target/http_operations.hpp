#pragma once

#include <string>
#include <vector>

namespace test_target {

struct HttpResponse {
    int status_code = 0;
    std::string body;
    bool success = false;
};

// WinHTTP operations
HttpResponse winhttp_get(const std::string& url);
HttpResponse winhttp_post(const std::string& url, const std::string& data);

// WinInet operations
HttpResponse wininet_get(const std::string& url);
HttpResponse wininet_post(const std::string& url, const std::string& data);

// URLMon download
bool urlmon_download(const std::string& url, const std::string& filename);

// Raw Winsock operation
bool winsock_connect_test(const std::string& host, int port);

}  // namespace test_target
