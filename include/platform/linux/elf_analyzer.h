// elf_analyzer.h - ELF 파일 분석 및 Java 실행파일 탐지
#pragma once

#include <elf.h>

#ifdef __cplusplus
extern "C" {
#endif

// ELF 분석 결과 구조체
typedef struct {
    int is_elf;
    int is_64bit;
    int is_java_program;
    int is_dynamically_linked;
    char interpreter[256];
    char* java_home;
    char* main_class;
} elf_analysis_t;

// ELF 파일 분석 함수들
int analyze_elf_file(const char* filepath, elf_analysis_t* result);
int is_java_executable(const char* filepath);
int detect_jvm_libraries(void);
void init_java_detection(void);

// Java 프로그램 탐지 관련
int check_java_environment(void);
int is_jvm_process(void);
char* find_java_home(void);

#ifdef __cplusplus
}
#endif