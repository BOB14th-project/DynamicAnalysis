// foo_hook.cpp
#include "pch.h"
#include "hook_common.h"
#include "log.h"
#include "resolver.h"
#include <time.h>

using foo_fn = void(*)(int,int);
static foo_fn real_foo = nullptr;

static inline double now_ms() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

extern "C" void foo(int a, int b) {
    if (!real_foo) {
        real_foo = (foo_fn)resolve_next_symbol("foo");
        if (!real_foo) {
            // 원본이 없으면 NOP로 처리 (혹은 리턴)
            hook_log("[foo_hook] original foo not found\n");
            return;
        }
    }

    double t0 = now_ms();
    hook_log("[HOOKED] foo(%d,%d) intercepted, sum=%d\n", a, b, a+b);

    // 원본 호출
    real_foo(a, b);

    double t1 = now_ms();
    hook_log("[HOOKED] foo() total %.3f ms\n", t1 - t0);
}
