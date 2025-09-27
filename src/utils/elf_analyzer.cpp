// elf_analyzer.cpp - ELF 파일 분석 및 Java 실행파일 탐지 구현
#include "pch.h"
#include "elf_analyzer.h"
#include "hook_common.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// ELF 파일 분석
int analyze_elf_file(const char* filepath, elf_analysis_t* result) {
    if (!filepath || !result) return 0;
    
    memset(result, 0, sizeof(elf_analysis_t));
    
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return 0;
    
    // ELF 헤더 읽기
    Elf64_Ehdr ehdr64;
    Elf32_Ehdr ehdr32;
    
    if (read(fd, &ehdr64, sizeof(ehdr64)) != sizeof(ehdr64)) {
        close(fd);
        return 0;
    }
    
    // ELF 매직 넘버 확인
    if (memcmp(ehdr64.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return 0;
    }
    
    result->is_elf = 1;
    
    // 32bit vs 64bit 확인
    if (ehdr64.e_ident[EI_CLASS] == ELFCLASS64) {
        result->is_64bit = 1;
    } else if (ehdr64.e_ident[EI_CLASS] == ELFCLASS32) {
        result->is_64bit = 0;
        // 32비트인 경우 다시 읽기
        lseek(fd, 0, SEEK_SET);
        read(fd, &ehdr32, sizeof(ehdr32));
    }
    
    // 동적 링크 여부 확인 (ET_DYN 또는 PT_INTERP 세그먼트 존재)
    if (result->is_64bit) {
        if (ehdr64.e_type == ET_DYN) {
            result->is_dynamically_linked = 1;
        }
        
        // 프로그램 헤더 분석
        if (ehdr64.e_phnum > 0) {
            Elf64_Phdr* phdrs = (Elf64_Phdr*)malloc(ehdr64.e_phentsize * ehdr64.e_phnum);
            if (phdrs) {
                lseek(fd, ehdr64.e_phoff, SEEK_SET);
                read(fd, phdrs, ehdr64.e_phentsize * ehdr64.e_phnum);
                
                for (int i = 0; i < ehdr64.e_phnum; i++) {
                    if (phdrs[i].p_type == PT_INTERP) {
                        result->is_dynamically_linked = 1;
                        
                        // 인터프리터 경로 읽기
                        if (phdrs[i].p_filesz < sizeof(result->interpreter)) {
                            lseek(fd, phdrs[i].p_offset, SEEK_SET);
                            read(fd, result->interpreter, phdrs[i].p_filesz);
                            result->interpreter[phdrs[i].p_filesz] = '\0';
                        }
                        break;
                    }
                }
                free(phdrs);
            }
        }
    } else {
        // 32비트 처리 (유사하게 구현)
        if (ehdr32.e_type == ET_DYN) {
            result->is_dynamically_linked = 1;
        }
    }
    
    close(fd);
    
    // Java 실행파일 탐지
    result->is_java_program = is_java_executable(filepath);
    
    return 1;
}

// Java 실행파일인지 확인
int is_java_executable(const char* filepath) {
    if (!filepath) return 0;
    
    // 1. 파일명 기반 탐지
    const char* basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    
    if (strcmp(basename, "java") == 0 || 
        strstr(basename, "java") != nullptr ||
        strstr(basename, "openjdk") != nullptr) {
        return 1;
    }
    
    // 2. 파일 내용 분석 - Java 클래스 파일 시그니처 확인
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return 0;
    
    char magic[4];
    if (read(fd, magic, 4) == 4) {
        // Java 클래스 파일 매직 넘버 (0xCAFEBABE)
        if (magic[0] == (char)0xCA && magic[1] == (char)0xFE && 
            magic[2] == (char)0xBA && magic[3] == (char)0xBE) {
            close(fd);
            return 1;
        }
    }
    
    // 3. JAR 파일 시그니처 확인 (ZIP 시그니처)
    lseek(fd, 0, SEEK_SET);
    char zip_sig[4];
    if (read(fd, zip_sig, 4) == 4) {
        if (zip_sig[0] == 'P' && zip_sig[1] == 'K' && 
            zip_sig[2] == 0x03 && zip_sig[3] == 0x04) {
            close(fd);
            return 1;
        }
    }
    
    close(fd);
    
    // 4. 환경 기반 탐지
    return check_java_environment();
}

// Java 환경 확인
int check_java_environment(void) {
    // JAVA_HOME 환경 변수 확인
    char* java_home = getenv("JAVA_HOME");
    if (java_home) return 1;
    
    // 클래스패스 확인
    char* classpath = getenv("CLASSPATH");
    if (classpath && strlen(classpath) > 0) return 1;
    
    // Java 관련 시스템 속성 확인
    char* java_version = getenv("JAVA_VERSION");
    if (java_version) return 1;
    
    return 0;
}

// 현재 프로세스가 JVM 프로세스인지 확인
int is_jvm_process(void) {
    // /proc/self/maps에서 JVM 라이브러리 탐지
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    
    char line[1024];
    int found_jvm = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libjvm.so") ||
            strstr(line, "libhotspot.so") ||
            strstr(line, "libj9vm") ||
            strstr(line, "java") ||
            strstr(line, "jdk") ||
            strstr(line, "jre")) {
            found_jvm = 1;
            break;
        }
    }
    
    fclose(maps);
    return found_jvm;
}

// JVM 관련 라이브러리 탐지
int detect_jvm_libraries(void) {
    const char* jvm_libs[] = {
        "libjvm.so",
        "libhotspot.so", 
        "libj9vm.so",
        "libjava.so",
        "libverify.so",
        "libzip.so",
        nullptr
    };
    
    for (int i = 0; jvm_libs[i]; i++) {
        void* handle = dlopen(jvm_libs[i], RTLD_LAZY | RTLD_NOLOAD);
        if (handle) {
            dlclose(handle);
            if (hook_is_verbose()) {
                char log_msg[128];
                int n = snprintf(log_msg, sizeof(log_msg),
                               "[ELF] Detected JVM library: %s\n", jvm_libs[i]);
                write(STDERR_FILENO, log_msg, n);
            }
            return 1;
        }
    }
    
    return 0;
}

// JAVA_HOME 찾기
char* find_java_home(void) {
    // 환경 변수에서 찾기
    char* java_home = getenv("JAVA_HOME");
    if (java_home) {
        return strdup(java_home);
    }
    
    // 일반적인 Java 설치 경로들 확인
    const char* common_paths[] = {
        "/usr/lib/jvm/default-java",
        "/usr/lib/jvm/java-11-openjdk",
        "/usr/lib/jvm/java-8-openjdk", 
        "/usr/java/latest",
        "/opt/java",
        "/System/Library/Java/JavaVirtualMachines/1.6.0/Contents/Home",
        nullptr
    };
    
    for (int i = 0; common_paths[i]; i++) {
        struct stat st;
        if (stat(common_paths[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            return strdup(common_paths[i]);
        }
    }
    
    return nullptr;
}

// Java 탐지 초기화
void init_java_detection(void) {
    if (hook_is_verbose()) {
        write(STDERR_FILENO, "[ELF] Java detection initialized\n", 33);
        
        // 현재 프로세스 분석
        if (is_jvm_process()) {
            write(STDERR_FILENO, "[ELF] Running inside JVM process\n", 33);
        }
        
        // JVM 라이브러리 탐지
        if (detect_jvm_libraries()) {
            write(STDERR_FILENO, "[ELF] JVM libraries detected\n", 29);
        }
        
        // JAVA_HOME 확인
        char* java_home = find_java_home();
        if (java_home) {
            char log_msg[256];
            int n = snprintf(log_msg, sizeof(log_msg), 
                           "[ELF] JAVA_HOME: %s\n", java_home);
            write(STDERR_FILENO, log_msg, n);
            free(java_home);
        }
    }
}