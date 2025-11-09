#pragma once

#include <string>

namespace test_target {

// Proxy configuration test
bool test_proxy_settings();

// Multiple connection test
void stress_test_connections(int count);

}  // namespace test_target
