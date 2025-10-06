#include "common/pch.h"
#include "common/dynamic_analysis.h"

#include <filesystem>
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc == 2) {
        std::filesystem::path target(argv[1]);
        std::filesystem::path dir = target.parent_path();
        std::string directory = dir.empty() ? std::string(".") : dir.string();
        std::string name = target.filename().string();
        return dynamic_analysis(directory, name);
    }

    if (argc == 3) {
        return dynamic_analysis(argv[1], argv[2]);
    }

    std::cerr << "Usage: " << argv[0] << " <binary-path>" << '\n';
    std::cerr << "   or: " << argv[0] << " <directory> <binary-name>" << '\n';
    return 1;
}
