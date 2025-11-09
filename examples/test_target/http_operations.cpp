#include "http_operations.hpp"

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <urlmon.h>
#include <iostream>
#include <cstring>

// Prevent wininet.h conflicts by manually declaring what we need
#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID HINTERNET;

HINTERNET WINAPI InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
HINTERNET WINAPI InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
HINTERNET WINAPI HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
BOOL WINAPI HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
BOOL WINAPI InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
BOOL WINAPI InternetCloseHandle(HINTERNET hInternet);

#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define INTERNET_FLAG_RELOAD 0x80000000
#define INTERNET_FLAG_SECURE 0x00800000
#define INTERNET_SERVICE_HTTP 3
#define INTERNET_DEFAULT_HTTPS_PORT 443

#ifdef __cplusplus
}
#endif

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")

namespace test_target {

HttpResponse winhttp_get(const std::string& url) {
    HttpResponse response;

    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS urlComp = {sizeof(urlComp)};
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        return response;
    }

    HINTERNET hSession = WinHttpOpen(L"ExLoader Test Target/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS,
                                      0);
    if (!hSession) return response;

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return response;
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, nullptr,
                                             WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                           WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, nullptr)) {

        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           nullptr, &statusCode, &size, nullptr);
        response.status_code = statusCode;

        DWORD bytesAvailable = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            std::vector<char> buffer(bytesAvailable + 1);
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                buffer[bytesRead] = '\0';
                response.body.append(buffer.data(), bytesRead);
            }
        }
        response.success = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

HttpResponse winhttp_post(const std::string& url, const std::string& data) {
    HttpResponse response;

    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS urlComp = {sizeof(urlComp)};
    wchar_t host[256] = {0};
    wchar_t path[1024] = {0};

    urlComp.lpszHostName = host;
    urlComp.dwHostNameLength = _countof(host);
    urlComp.lpszUrlPath = path;
    urlComp.dwUrlPathLength = _countof(path);

    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        return response;
    }

    HINTERNET hSession = WinHttpOpen(L"ExLoader Test Target/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return response;

    HINTERNET hConnect = WinHttpConnect(hSession, host, urlComp.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return response;
    }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path, nullptr,
                                             WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (WinHttpSendRequest(hRequest, headers.c_str(), -1,
                           const_cast<char*>(data.c_str()), data.length(),
                           data.length(), 0) &&
        WinHttpReceiveResponse(hRequest, nullptr)) {

        DWORD statusCode = 0;
        DWORD size = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           nullptr, &statusCode, &size, nullptr);
        response.status_code = statusCode;

        DWORD bytesAvailable = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            std::vector<char> buffer(bytesAvailable + 1);
            DWORD bytesRead = 0;
            if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                buffer[bytesRead] = '\0';
                response.body.append(buffer.data(), bytesRead);
            }
        }
        response.success = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

HttpResponse wininet_get(const std::string& url) {
    HttpResponse response;

    HINTERNET hInternet = InternetOpenA("ExLoader Test Target/1.0",
                                        INTERNET_OPEN_TYPE_PRECONFIG,
                                        nullptr, nullptr, 0);
    if (!hInternet) return response;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0,
                                      INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return response;
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response.body.append(buffer, bytesRead);
    }

    response.success = true;
    response.status_code = 200;

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    return response;
}

HttpResponse wininet_post(const std::string& url, const std::string& data) {
    HttpResponse response;

    // Parse URL
    size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return response;

    size_t hostStart = schemeEnd + 3;
    size_t pathStart = url.find('/', hostStart);

    std::string host = (pathStart != std::string::npos)
        ? url.substr(hostStart, pathStart - hostStart)
        : url.substr(hostStart);
    std::string path = (pathStart != std::string::npos)
        ? url.substr(pathStart)
        : "/";

    HINTERNET hInternet = InternetOpenA("ExLoader Test Target/1.0",
                                        INTERNET_OPEN_TYPE_PRECONFIG,
                                        nullptr, nullptr, 0);
    if (!hInternet) return response;

    HINTERNET hConnect = InternetConnectA(hInternet, host.c_str(),
                                          INTERNET_DEFAULT_HTTPS_PORT,
                                          nullptr, nullptr,
                                          INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return response;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path.c_str(),
                                          nullptr, nullptr, nullptr,
                                          INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return response;
    }

    const char* headers = "Content-Type: application/json\r\n";
    if (HttpSendRequestA(hRequest, headers, -1,
                        const_cast<char*>(data.c_str()), data.length())) {

        char buffer[4096];
        DWORD bytesRead = 0;
        while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            response.body.append(buffer, bytesRead);
        }
        response.success = true;
        response.status_code = 200;
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

bool urlmon_download(const std::string& url, const std::string& filename) {
    std::wstring wurl(url.begin(), url.end());
    std::wstring wfilename(filename.begin(), filename.end());

    HRESULT hr = URLDownloadToFileW(nullptr, wurl.c_str(), wfilename.c_str(), 0, nullptr);
    return SUCCEEDED(hr);
}

bool winsock_connect_test(const std::string& host, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    hostent* he = gethostbyname(host.c_str());
    if (!he) {
        closesocket(sock);
        WSACleanup();
        return false;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = *reinterpret_cast<in_addr*>(he->h_addr);

    bool success = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;

    if (success) {
        const char* request = "GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n";
        send(sock, request, strlen(request), 0);

        char buffer[1024];
        recv(sock, buffer, sizeof(buffer) - 1, 0);
    }

    closesocket(sock);
    WSACleanup();

    return success;
}

}  // namespace test_target
