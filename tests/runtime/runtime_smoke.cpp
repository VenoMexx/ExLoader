#include <cassert>
#include <string>

#include "exloader/runtime/runtime_api.hpp"

int main() {
    exloader::runtime::Runtime runtime;
    exloader::runtime::RuntimeOptions options{};
    options.profile_name = "test-profile";
    options.requested_modules = {
        {"mod.one", "1.0.0", true},
        {"mod.two", "1.1.0", false}};

    runtime.configure(options);
    const std::string summary = runtime.summary();
    assert(summary.find("test-profile") != std::string::npos);
    assert(summary.find("mod.one") != std::string::npos);
    assert(summary.find("disabled") != std::string::npos);
    return 0;
}
