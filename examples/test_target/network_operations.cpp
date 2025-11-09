#include "network_operations.hpp"
#include "http_operations.hpp"

#include <windows.h>
#include <winhttp.h>
#include <iostream>

// Manually declare WinInet functions to avoid header conflicts
#ifdef __cplusplus
extern "C" {
#endif

typedef LPVOID HINTERNET;

HINTERNET WINAPI InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
BOOL WINAPI InternetCloseHandle(HINTERNET hInternet);
BOOL WINAPI InternetQueryOptionA(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength);

#define INTERNET_OPEN_TYPE_PRECONFIG 0
#define INTERNET_OPTION_PER_CONNECTION_OPTION 75
#define INTERNET_PER_CONN_FLAGS 1
#define INTERNET_PER_CONN_PROXY_SERVER 2
#define INTERNET_PER_CONN_PROXY_BYPASS 3

typedef struct {
    DWORD dwOption;
    union {
        DWORD dwValue;
        LPSTR pszValue;
        FILETIME ftValue;
    } Value;
} INTERNET_PER_CONN_OPTION, *LPINTERNET_PER_CONN_OPTION;

typedef struct {
    DWORD dwSize;
    LPSTR pszConnection;
    DWORD dwOptionCount;
    DWORD dwOptionError;
    LPINTERNET_PER_CONN_OPTION pOptions;
} INTERNET_PER_CONN_OPTION_LIST, *LPINTERNET_PER_CONN_OPTION_LIST;

#ifdef __cplusplus
}
#endif

namespace test_target {

bool test_proxy_settings() {
    // Test WinHTTP proxy settings
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = {};
    if (WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
        if (proxyConfig.lpszProxy) {
            GlobalFree(proxyConfig.lpszProxy);
        }
        if (proxyConfig.lpszProxyBypass) {
            GlobalFree(proxyConfig.lpszProxyBypass);
        }
        if (proxyConfig.lpszAutoConfigUrl) {
            GlobalFree(proxyConfig.lpszAutoConfigUrl);
        }
    }

    // Test WinInet proxy settings
    HINTERNET hInternet = InternetOpenA("Test", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (hInternet) {
        INTERNET_PER_CONN_OPTION_LIST list = {};
        INTERNET_PER_CONN_OPTION options[3] = {};

        options[0].dwOption = INTERNET_PER_CONN_FLAGS;
        options[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        options[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;

        list.dwSize = sizeof(list);
        list.pszConnection = nullptr;
        list.dwOptionCount = 3;
        list.pOptions = options;

        DWORD size = sizeof(list);
        InternetQueryOptionA(hInternet, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &size);

        InternetCloseHandle(hInternet);
    }

    return true;
}

void stress_test_connections(int count) {
    for (int i = 0; i < count; ++i) {
        // Alternate between different APIs
        if (i % 3 == 0) {
            winhttp_get("https://httpbin.org/delay/1");
        } else if (i % 3 == 1) {
            wininet_get("https://httpbin.org/delay/1");
        } else {
            winsock_connect_test("httpbin.org", 80);
        }
    }
}

}  // namespace test_target
