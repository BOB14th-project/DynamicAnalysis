// log.cpp
#define _GNU_SOURCE
#include "pch.h"
#include "log.h"
#include "hook_common.h"

#include <string.h>
#include <stdarg.h>

static int log_fd = -1;
static pthread_once_t log_once = PTHREAD_ONCE_INIT;

static void open_log_target(void) {
    const char* path = getenv(HOOK_ENV_LOGFILE);
    if (path && *path) {
        int fd = open(path, O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (fd >= 0) { log_fd = fd; return; }
    }
    log_fd = STDERR_FILENO; // fallback
}

static void vwritef(const char* fmt, va_list ap) {
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n < 0) return;
    if (n > (int)sizeof(buf)) n = (int)sizeof(buf);
    if (log_fd < 0) pthread_once(&log_once, open_log_target);
    (void)!write(log_fd, buf, (size_t)n);
}

void hook_log(const char* fmt, ...) {
    if (!hook_is_verbose()) return;
    va_list ap; va_start(ap, fmt);
    vwritef(fmt, ap);
    va_end(ap);
}

void hook_log_raw(const char* s, size_t n) {
    if (log_fd < 0) pthread_once(&log_once, open_log_target);
    (void)!write(log_fd, s, n);
}
