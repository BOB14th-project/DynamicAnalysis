#include "common/pch.h"
#include "platform/linux/resolver.h"
#include "platform/linux/log.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {

pthread_once_t g_once = PTHREAD_ONCE_INIT;
std::mutex g_cache_mu;
std::unordered_map<std::string, void*> g_symbol_cache;

void resolver_init_internal() {
    // Placeholder for future expansion; currently ensures pthread_once firing.
}

void* resolve_symbol_with_cache(const std::string& key,
                                std::function<void*()> loader) {
    {
        std::lock_guard<std::mutex> lock(g_cache_mu);
        auto it = g_symbol_cache.find(key);
        if (it != g_symbol_cache.end()) {
            return it->second;
        }
    }

    void* sym = loader ? loader() : nullptr;
    {
        std::lock_guard<std::mutex> lock(g_cache_mu);
        g_symbol_cache.emplace(key, sym);
    }
    return sym;
}

} // namespace

void resolver_init_once(void) {
    pthread_once(&g_once, resolver_init_internal);
}

void* resolve_next_symbol(const char* name) {
    if (!name || !*name) {
        return nullptr;
    }
    resolver_init_once();

    auto loader = [name]() -> void* {
        void* result = dlsym(RTLD_NEXT, name);
        if (!result) {
            if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
                hook_log("[resolver] failed to resolve '%s': %s\n", name, dlerror());
            }
        }
        return result;
    };

    return resolve_symbol_with_cache(std::string("next:") + name, loader);
}

void* resolve_in_lib(const char* soname, const char* sym) {
    if (!soname || !*soname || !sym || !*sym) {
        return nullptr;
    }
    resolver_init_once();

    std::string cache_key = std::string("lib:") + soname + ":" + sym;
    auto loader = [soname, sym]() -> void* {
        void* handle = dlopen(soname, RTLD_LAZY | RTLD_LOCAL);
        if (!handle) {
            if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
                hook_log("[resolver] dlopen('%s') failed: %s\n", soname, dlerror());
            }
            return nullptr;
        }
        void* result = dlsym(handle, sym);
        if (!result) {
            if (const char* verbose = std::getenv("HOOK_VERBOSE"); verbose && *verbose == '1') {
                hook_log("[resolver] dlsym('%s','%s') failed: %s\n", soname, sym, dlerror());
            }
        }
        return result;
    };

    return resolve_symbol_with_cache(cache_key, loader);
}
