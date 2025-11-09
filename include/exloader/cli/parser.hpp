#pragma once

#include "exloader/cli/cli_options.hpp"

namespace exloader::cli {

class Parser {
public:
    Options parse(int argc, char** argv) const;
};

}  // namespace exloader::cli
