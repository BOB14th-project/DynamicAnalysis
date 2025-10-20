#include "common/pch.h"
#include "common/output.h"
#include "platform/linux/log.h"

#include <cstdio>

namespace {

inline bool verbose_mode() {
    const char* env = std::getenv("HOOK_VERBOSE");
    return env && *env == '1';
}

} // namespace

__attribute__((constructor))
static void hook_init_ctor() {
    ndjson_init_from_env();
    if (verbose_mode()) {
        std::fprintf(stderr, "[hook_linux] libhook.so loaded\n");
    }
}

__attribute__((destructor))
static void hook_init_dtor() {
    if (verbose_mode()) {
        std::fprintf(stderr, "[hook_linux] libhook.so unloaded\n");
    }
}

