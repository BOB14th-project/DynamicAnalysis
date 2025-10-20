// src/platform/mac/core/init.cpp
#include "common/pch.h"
#include "platform/mac/resolver.h"
#include "common/output.h"

#include <dlfcn.h>
#include <cstdio>

__attribute__((constructor))
static void on_load() {
    const char* verbose_env = std::getenv("HOOK_VERBOSE");
    if (verbose_env && *verbose_env == '1') {
        std::fprintf(stderr, "[hook_macos] libhook.dylib loaded (macOS ARM support enabled)\n");
    }
}

__attribute__((destructor))
static void on_unload() {
    const char* verbose_env = std::getenv("HOOK_VERBOSE");
    if (verbose_env && *verbose_env == '1') {
        std::fprintf(stderr, "[hook_macos] libhook.dylib unloaded\n");
    }
}
