// init.cpp
#include "pch.h"
#include "hook_common.h"
#include "resolver.h"
#include "log.h"

static int g_verbose = 0;

extern "C" int hook_is_verbose(void) { return g_verbose; }

extern "C" void hook_runtime_init(void) {
    const char* v = std::getenv(HOOK_ENV_VERBOSE);
    g_verbose = (v && *v && v[0] != '0') ? 1 : 0;
    resolver_init_once();
    hook_log("[hook] runtime init (verbose=%d)\n", g_verbose);
}

__attribute__((constructor))
static void ctor(void) {
    hook_runtime_init();
}
