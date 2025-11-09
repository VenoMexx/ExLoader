#include "exloader/runtime/hooks/crypto/key_store.hpp"

namespace exloader::runtime::hooks::crypto {

void KeyStore::register_algorithm(void* handle, std::string_view alg_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    algorithms_[handle] = std::string(alg_name);
}

std::optional<std::string> KeyStore::algorithm_for(void* handle) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = algorithms_.find(handle);
    if (it == algorithms_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void KeyStore::upsert_key(void* handle, KeyMetadata metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    keys_[handle] = std::move(metadata);
}

std::optional<KeyMetadata> KeyStore::metadata_for(void* handle) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = keys_.find(handle);
    if (it == keys_.end()) {
        return std::nullopt;
    }
    return it->second;
}

void KeyStore::remove_key(void* handle) {
    std::lock_guard<std::mutex> lock(mutex_);
    keys_.erase(handle);
}

}  // namespace exloader::runtime::hooks::crypto
