// src/platform/mac/core/resolver.cpp
#include "common/pch.h"
#include "platform/mac/resolver.h"

#include <dlfcn.h>
#include <cstdio>
#include <cstring>

void* resolve_next_symbol(const char* name) {
    if (!name || !*name) return nullptr;

    void* sym = dlsym(RTLD_NEXT, name);

    const char* verbose_env = std::getenv("HOOK_VERBOSE");
    if (verbose_env && *verbose_env == '1') {
        if (sym) {
            std::fprintf(stderr, "[resolver_macos] resolved '%s' at %p\n", name, sym);
        } else {
            std::fprintf(stderr, "[resolver_macos] failed to resolve '%s': %s\n", name, dlerror());
        }
    }

    return sym;
}
