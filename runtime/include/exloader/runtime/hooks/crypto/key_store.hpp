#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <mutex>

namespace exloader::runtime::hooks::crypto {

struct KeyMetadata {
    std::string algorithm;
    std::string key_hex;
    std::size_t key_size{0};
};

class KeyStore {
public:
    void register_algorithm(void* handle, std::string_view alg_name);
    std::optional<std::string> algorithm_for(void* handle) const;

    void upsert_key(void* handle, KeyMetadata metadata);
    std::optional<KeyMetadata> metadata_for(void* handle) const;
    void remove_key(void* handle);

private:
    mutable std::mutex mutex_;
    std::unordered_map<void*, std::string> algorithms_;
    std::unordered_map<void*, KeyMetadata> keys_;
};

}  // namespace exloader::runtime::hooks::crypto
