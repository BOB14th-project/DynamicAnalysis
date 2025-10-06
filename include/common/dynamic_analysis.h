#pragma once

#include <string>

// Runs dynamic analysis for the given binary residing at directory/binary_name.
// Returns 0 on success, non-zero otherwise.
int dynamic_analysis(const std::string& directory, const std::string& binary_name);
