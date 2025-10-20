#include "common/pch.h"
#include "platform/linux/log.h"

#include <cstdarg>
#include <cstdio>

namespace {

inline int stderr_fd() {
    return STDERR_FILENO;
}

} // namespace

void hook_log(const char* fmt, ...) {
    if (!fmt) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    std::vdprintf(stderr_fd(), fmt, args);
    va_end(args);
}

void hook_log_raw(const char* s, size_t n) {
    if (!s || n == 0) {
        return;
    }

    while (n > 0) {
        ssize_t written = write(stderr_fd(), s, n);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        s += written;
        n -= static_cast<size_t>(written);
    }
}

