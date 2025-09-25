// resolver.h
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// 스레드 안전 1회 초기화
void resolver_init_once(void);

// 시그니처에 맞춰 캐스팅해서 받기
void* resolve_next_symbol(const char* name);   // RTLD_NEXT
// 필요하면 특정 라이브러리에서 찾는 버전도 추가
void* resolve_in_lib(const char* soname, const char* sym);

#ifdef __cplusplus
}
#endif
