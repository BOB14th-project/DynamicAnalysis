// java_process_detector.cpp - Java 프로세스 탐지 도구 (Linux 전용)
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <cstring>

// 간단한 스텁 함수들 - hook 라이브러리 의존성 제거
extern "C" int hook_is_verbose(void) { return 1; }
extern "C" void hook_log(const char* fmt, ...) { (void)fmt; }

// ELF 분석 함수들을 직접 구현
static int analyze_elf_simple(const char* filepath) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) return 0;
    
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        close(fd);
        return 0;
    }
    
    int is_elf = (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0);
    close(fd);
    return is_elf;
}

static int is_java_binary(const char* filepath) {
    const char* basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    
    return (strcmp(basename, "java") == 0 || 
            strstr(basename, "java") != nullptr ||
            strstr(basename, "openjdk") != nullptr);
}

static int check_jvm_in_memory() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    
    char line[1024];
    int found = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "libjvm.so") ||
            strstr(line, "libhotspot.so") ||
            strstr(line, "java")) {
            found = 1;
            break;
        }
    }
    
    fclose(maps);
    return found;
}

class JavaProcessAnalyzer {
public:
    void analyzeCurrentProcess() {
        std::cout << "=== Java Process Analysis ===" << std::endl;
        
        // 1. 현재 프로세스가 JVM 프로세스인지 확인
        if (check_jvm_in_memory()) {
            std::cout << "✓ Running inside JVM process" << std::endl;
        } else {
            std::cout << "✗ Not a JVM process" << std::endl;
        }
        
        // 2. Java 환경 확인
        char* java_home = getenv("JAVA_HOME");
        if (java_home) {
            std::cout << "✓ JAVA_HOME: " << java_home << std::endl;
        } else {
            std::cout << "✗ JAVA_HOME not found" << std::endl;
        }
        
        char* classpath = getenv("CLASSPATH");
        if (classpath && strlen(classpath) > 0) {
            std::cout << "✓ CLASSPATH: " << classpath << std::endl;
        } else {
            std::cout << "✗ CLASSPATH not set" << std::endl;
        }
        
        // 3. 프로세스 메모리 맵 분석
        analyzeMemoryMaps();
    }
    
    void analyzeELFFile(const char* filepath) {
        std::cout << "\n=== ELF File Analysis: " << filepath << " ===" << std::endl;
        
        struct stat st;
        if (stat(filepath, &st) != 0) {
            std::cout << "File not found or inaccessible" << std::endl;
            return;
        }
        
        int is_elf = analyze_elf_simple(filepath);
        int is_java = is_java_binary(filepath);
        
        std::cout << "File type: " << (is_elf ? "ELF" : "Non-ELF") << std::endl;
        std::cout << "File size: " << st.st_size << " bytes" << std::endl;
        std::cout << "Java executable: " << (is_java ? "Yes" : "No") << std::endl;
        
        if (is_elf) {
            std::cout << "✓ Valid ELF file" << std::endl;
        }
        
        if (is_java) {
            std::cout << "✓ Appears to be Java-related executable" << std::endl;
        }
    }
    
private:
    void analyzeMemoryMaps() {
        std::cout << "\n--- Memory Maps Analysis ---" << std::endl;
        
        std::ifstream maps("/proc/self/maps");
        std::string line;
        std::vector<std::string> java_libs;
        
        while (std::getline(maps, line)) {
            if (line.find("java") != std::string::npos ||
                line.find("jvm") != std::string::npos ||
                line.find("jdk") != std::string::npos ||
                line.find("jre") != std::string::npos ||
                line.find("hotspot") != std::string::npos) {
                
                // 라이브러리 경로 추출
                size_t space_pos = line.find_last_of(' ');
                if (space_pos != std::string::npos) {
                    std::string lib_path = line.substr(space_pos + 1);
                    java_libs.push_back(lib_path);
                }
            }
        }
        
        if (!java_libs.empty()) {
            std::cout << "Java-related libraries found:" << std::endl;
            for (const auto& lib : java_libs) {
                std::cout << "  - " << lib << std::endl;
            }
        } else {
            std::cout << "No Java-related libraries found in memory" << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    std::cout << "Java Process & ELF Analyzer" << std::endl;
    std::cout << "============================" << std::endl;
    
    JavaProcessAnalyzer analyzer;
    
    // 현재 프로세스 분석
    analyzer.analyzeCurrentProcess();
    
    // 명령행 인수로 전달된 파일들 분석
    for (int i = 1; i < argc; i++) {
        analyzer.analyzeELFFile(argv[i]);
    }
    
    // 일반적인 Java 실행파일들 분석
    std::vector<std::string> common_java_files = {
        "/usr/bin/java",
        "/usr/bin/javac", 
        "/usr/lib/jvm/default-java/bin/java",
        "/usr/lib/jvm/java-11-openjdk-amd64/bin/java"
    };
    
    std::cout << "\n=== Common Java Binaries Analysis ===" << std::endl;
    for (const auto& file : common_java_files) {
        struct stat st;
        if (stat(file.c_str(), &st) == 0) {
            analyzer.analyzeELFFile(file.c_str());
        }
    }
    
    return 0;
}
