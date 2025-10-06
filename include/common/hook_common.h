// hook_common.h
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// 환경변수 키 (예: 출력 레벨, 로그 경로)
#define HOOK_ENV_VERBOSE   "HOOK_VERBOSE"   // "0|1"
#define HOOK_ENV_LOGFILE   "HOOK_LOGFILE"   // 파일 경로, 없으면 stderr

void hook_runtime_init(void);   // constructor에서 호출
int  hook_is_verbose(void);

#ifdef __cplusplus
}
#endif
