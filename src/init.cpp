// init.cpp
#include "pch.h"
#include "hook_common.h"
#include "resolver.h"
#include "log.h"
#include "elf_analyzer.h"
#include "output.h"

#ifdef JAVA_SUPPORT_ENABLED
#include "hook_jni.h"
#endif

static int g_verbose = 0;

extern "C" int hook_is_verbose(void) { return g_verbose; }

extern "C" void hook_runtime_init(void) {
    const char* v = std::getenv(HOOK_ENV_VERBOSE);
    g_verbose = (v && *v && v[0] != '0') ? 1 : 0;
    resolver_init_once();
    
    // Java 탐지 및 후킹 초기화
    init_java_detection();
    
#ifdef JAVA_SUPPORT_ENABLED
    int java_detected = 0;
    if (is_jvm_process() || detect_jvm_libraries()) {
        java_detected = 1;
        hook_java_crypto_init();
        hook_log("[hook] Java crypto hooks enabled\n");
    }
    if (java_detected) {
        ndjson_init_from_env();
        // 안내용 이벤트: 순수 JCE 환경은 별도 JVMTI 계측이 필요함
        ndjson_log_key_event("java_runtime",
                             "jvm_detected",
                             "info",
                             "Use JVMTI/Instrumentation for pure JCE",
                             nullptr,
                             0,
                             nullptr,
                             0,
                             nullptr,
                             0);
    }
#endif
    
    hook_log("[hook] runtime init (verbose=%d)\n", g_verbose);
}

__attribute__((constructor))
static void ctor(void) {
    hook_runtime_init();
}
