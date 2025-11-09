#include "exloader/runtime/hooks/event_utils.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#endif

namespace exloader::runtime::hooks {

CallerInfo resolve_caller(void* return_address) {
    CallerInfo info{};
#if defined(_WIN32)
    HMODULE module = nullptr;
    if (GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            static_cast<LPCSTR>(return_address), &module)) {
        char path[MAX_PATH];
        DWORD len = GetModuleFileNameA(module, path, MAX_PATH);
        if (len != 0) {
            // Extract just the filename from the full path
            const char* filename = path;
            for (DWORD i = 0; i < len; ++i) {
                if (path[i] == '\\' || path[i] == '/') {
                    filename = path + i + 1;
                }
            }
            info.module.assign(filename);
        }
        info.offset = reinterpret_cast<std::uintptr_t>(return_address) -
                      reinterpret_cast<std::uintptr_t>(module);
    }
#endif
    return info;
}

std::string hex_encode(const void* data, std::size_t length, std::size_t max_bytes) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    const std::size_t emit = std::min(length, max_bytes);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < emit; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    if (emit < length) {
        oss << "...";
    }
    return oss.str();
}

void append_caller(nlohmann::json& json, const CallerInfo& caller) {
    if (!caller.module.empty()) {
        json["caller"] = {
            {"module", caller.module},
            {"offset", caller.offset}
        };
    }
}

}  // namespace exloader::runtime::hooks
