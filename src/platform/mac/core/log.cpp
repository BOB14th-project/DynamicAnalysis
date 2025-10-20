// src/platform/mac/core/log.cpp
#include "common/pch.h"
#include <cstdio>
#include <cstdlib>

void hook_log(const char* msg) {
    const char* verbose_env = std::getenv("HOOK_VERBOSE");
    if (verbose_env && *verbose_env == '1') {
        std::fprintf(stderr, "[hook_macos] %s\n", msg);
    }
}
