cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES CXX)

# ── 공통 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(_GNU_SOURCE)

# 아웃풋 디렉토리 정리
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 헤더 경로
include_directories(${CMAKE_SOURCE_DIR}/include)

# OpenSSL (훅/테스트에서 사용)
find_package(OpenSSL REQUIRED)

# Java JNI 지원 (선택적)
find_package(JNI)
if(JNI_FOUND)
    message(STATUS "JNI found: ${JNI_INCLUDE_DIRS}")
    add_compile_definitions(JAVA_SUPPORT_ENABLED)
    include_directories(${JNI_INCLUDE_DIRS})
else()
    message(WARNING "JNI not found - Java crypto hooks will be disabled")
endif()

# ── Hook 라이브러리 소스
set(HOOK_SRCS
    src/init.cpp
    src/log.cpp
    src/resolver.cpp
    src/hooks/foo_hook.cpp
    src/hooks/openssl_hooks.cpp
    src/utils/crypto_utils.cpp    
    src/utils/output.cpp    
    src/utils/elf_analyzer.cpp
)

# Java 지원이 가능한 경우 Java 관련 소스 추가
if(JNI_FOUND)
    list(APPEND HOOK_SRCS
        src/hooks/jni_hooks.cpp
        src/hooks/java_native_crypto_hooks.cpp
        src/utils/java_crypto_utils.cpp
    )
endif()

add_library(hook SHARED ${HOOK_SRCS})
target_precompile_headers(hook PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
target_link_libraries(hook PRIVATE dl pthread OpenSSL::Crypto)

# Java 지원이 가능한 경우 JNI 라이브러리 링크
if(JNI_FOUND)
    target_link_libraries(hook PRIVATE ${JNI_LIBRARIES})
endif()

# ── 핵심 테스트 실행파일들
add_executable(demo_target    tests/demo_target.cpp)
add_executable(aes_lib_test   tests/aes_lib_test.cpp)

# Java 지원이 가능한 경우 Java 테스트 추가
if(JNI_FOUND)
    add_executable(java_process_detector tests/java_process_detector.cpp)
    target_link_libraries(java_process_detector PRIVATE dl)
endif()

# 테스트 타깃에도 PCH 적용
set(TEST_TARGETS demo_target aes_lib_test)
if(JNI_FOUND)
    list(APPEND TEST_TARGETS java_process_detector)
endif()

foreach(tgt IN LISTS TEST_TARGETS)
  target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
endforeach()

# OpenSSL 필요한 테스트에 링크
target_link_libraries(aes_lib_test   PRIVATE OpenSSL::Crypto)

# ── 사용 힌트
message(STATUS "Build:  cmake -S . -B build && cmake --build build -j")
message(STATUS "Run:    HOOK_VERBOSE=1 LD_PRELOAD=${CMAKE_BINARY_DIR}/lib/libhook.so ${CMAKE_BINARY_DIR}/bin/aes_lib_test")
