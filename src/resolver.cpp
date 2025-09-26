// resolver.cpp
#include "pch.h"
#include "resolver.h"
#include "hook_common.h"
#include "log.h"

static pthread_once_t g_once = PTHREAD_ONCE_INIT;

void resolver_init_once(void) {
    // 지금은 할 일 없지만, 필요 시 전역 테이블/락 초기화
}

static void ensure_init(void) {
    pthread_once(&g_once, resolver_init_once);
}

void* resolve_next_symbol(const char* name) {
    ensure_init();
    dlerror();
    void* p = dlsym(RTLD_NEXT, name);
    const char* err = dlerror();
    if (err) {
        hook_log("[resolver] dlsym next failed: %s (%s)\n", name, err);
        return NULL;
    }
    return p;
}

void* resolve_in_lib(const char* soname, const char* sym) {
    ensure_init();
    dlerror();
    void* handle = dlopen(soname, RTLD_LAZY);
    if (!handle) {
        hook_log("[resolver] dlopen fail: %s\n", soname);
        return NULL;
    }
    void* p = dlsym(handle, sym);
    const char* err = dlerror();
    if (err) {
        hook_log("[resolver] dlsym %s!%s fail: %s\n", soname, sym, err);
        return NULL;
    }
    return p;
}
