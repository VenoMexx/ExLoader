#pragma once

#include "exloader/cli/cli_options.hpp"
#include "exloader/config/config_types.hpp"

namespace exloader::injector {

class InjectorApp {
public:
    int run(const cli::Options& options);

private:
    static void print_plan(const config::ProfileConfig& profile, bool attach_mode);
};

}  // namespace exloader::injector
