// log.h
#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 재귀 방지를 위해 write(2) 기반. (printf 금지)
void hook_log(const char* fmt, ...);
void hook_log_raw(const char* s, size_t n);

#ifdef __cplusplus
}
#endif
