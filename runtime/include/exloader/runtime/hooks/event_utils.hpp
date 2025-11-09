#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <nlohmann/json_fwd.hpp>

#if defined(_MSC_VER)
#include <intrin.h>
#define EXL_RETURN_ADDRESS() _ReturnAddress()
#else
#define EXL_RETURN_ADDRESS() __builtin_return_address(0)
#endif

namespace exloader::runtime::hooks {

struct CallerInfo {
    std::string module;
    std::uintptr_t offset{0};
};

CallerInfo resolve_caller(void* return_address);
std::string hex_encode(const void* data, std::size_t length, std::size_t max_bytes);
void append_caller(nlohmann::json& json, const CallerInfo& caller);

}  // namespace exloader::runtime::hooks
