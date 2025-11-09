#include <cstdio>

#include "exloader/cli/parser.hpp"
#include "exloader/injector/injector_app.hpp"

int main(int argc, char** argv) {
    exloader::cli::Parser parser;
    exloader::injector::InjectorApp app;

    try {
        auto options = parser.parse(argc, argv);
        return app.run(options);
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
}
