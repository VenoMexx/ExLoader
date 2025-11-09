#include "exloader/cli/parser.hpp"

#include <cstdlib>
#include <stdexcept>

#include <CLI11.hpp>

namespace exloader::cli {

Options Parser::parse(int argc, char** argv) const {
    CLI::App app{"ExLoader injector"};

    Options options{};
    app.add_option("--profile", options.profile, "JSON profile file")
        ->required()
        ->check(CLI::ExistingFile);
    app.add_option("--target", options.target_override, "Override executable path");
    app.add_option("--log", options.log_override, "Override JSONL log path");
    app.add_option("--args", options.target_args, "Arguments passed to the target process");
    app.add_option("--workdir", options.workdir_override, "Override working directory");
    app.add_option("--dll", options.dll_override, "Override runtime DLL to inject")
        ->check(CLI::ExistingFile);
    app.add_option("--pid", options.pid, "Attach to the given PID")->check(CLI::PositiveNumber);
    app.add_option("--method", options.injection_method,
                   "Injection method (remote-thread|apc-queue)");
    app.add_flag("--attach", options.attach, "Attach to an existing PID");
    app.add_flag("--follow", options.follow_logs, "Tail log file to stdout");
    app.add_flag("--validate", options.validate_only, "Validate profile and exit without injection");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // Print help/error message and exit with proper code
        std::exit(app.exit(e));
    }

    if (options.pid.has_value()) {
        options.attach = true;
    }

    return options;
}

}  // namespace exloader::cli
