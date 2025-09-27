cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES CXX)

# ── 공통 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_definitions(_GNU_SOURCE)

# 아웃풋 디렉토리 정리
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 헤더 경로
include_directories(${CMAKE_SOURCE_DIR}/include)

# OpenSSL 필요 (openssl 훅/테스트)
find_package(OpenSSL REQUIRED)

# ── 빌드 옵션
option(ENABLE_AF_ALG      "Build AF_ALG hook (Linux kernel crypto sockets)" ON)
option(ENABLE_CRYPTODEV   "Build cryptodev hook (ioctl-based)"              OFF)
option(HOOK_VERBOSE       "Verbose logging inside hooks"                    OFF)
option(HOOK_MASK          "Mask key/iv/tag in NDJSON (hash/trunc)"          OFF)

if(HOOK_VERBOSE)
  add_compile_definitions(HOOK_VERBOSE=1)
endif()
if(HOOK_MASK)
  add_compile_definitions(HOOK_MASK=1)
endif()
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
    src/utils/crypto_utils.cpp
    src/utils/output.cpp
    src/utils/elf_analyzer.cpp
)

if(UNIX)
    list(APPEND HOOK_SRCS
        src/Linux/hooks/hook_openssl_core.cpp
        src/Linux/hooks/hook_openssl_provider.cpp
        src/Linux/hooks/hook_openssl_ecc.cpp
    )

    if(ENABLE_AF_ALG)
        list(APPEND HOOK_SRCS src/Linux/hooks/hook_af_alg.cpp)
    endif()

    if(ENABLE_CRYPTODEV)
        list(APPEND HOOK_SRCS src/Linux/hooks/hook_cryptodev.cpp)
    endif()

    if(JNI_FOUND)
        list(APPEND HOOK_SRCS
        src/Linux/hooks/hook_jni.cpp
        src/Linux/hooks/hook_java_native_crypto.cpp
            src/utils/java_crypto_utils.cpp
        )
    endif()
else()
    message(WARNING "Non-Linux builds currently include only platform-agnostic sources")
endif()

add_library(hook SHARED ${HOOK_SRCS})
target_precompile_headers(hook PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
target_compile_options(hook PRIVATE -O2 -fPIC -fno-omit-frame-pointer -Wall -Wextra)
target_link_libraries(hook PRIVATE dl pthread OpenSSL::Crypto)

# Java 지원이 가능한 경우 JNI 라이브러리 링크
if(JNI_FOUND)
    target_link_libraries(hook PRIVATE ${JNI_LIBRARIES})
endif()

# ── OpenSSL 테스트 (암호화 경로별 커버리지)
add_executable(demo_target                  tests/openssl/demo/demo_target.cpp)
add_executable(aes_lib_test                 tests/openssl/symmetric/aes_lib_test.cpp)
add_executable(symm_aes_gcm_test            tests/openssl/aead/symm_aes_gcm_test.cpp)
add_executable(ecc_sign_test                tests/openssl/ecc/ecc_sign_test.cpp)
add_executable(ecc_ECIES_test               tests/openssl/ecc/ecc_ECIES_test.cpp)
add_executable(openssl3_ex2_test            tests/openssl/provider/openssl3_ex2_test.cpp)
add_executable(openssl3_ex2_params_test     tests/openssl/provider/openssl3_ex2_params_test.cpp)

# ── 동적 분석 CLI (LD_PRELOAD 주입 자동화)
add_executable(dynamic_analysis_cli src/main.cpp src/dynamic_analysis.cpp)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9")
    target_link_libraries(dynamic_analysis_cli PRIVATE stdc++fs)
endif()

# Java 지원이 가능한 경우 Java 테스트 추가
if(JNI_FOUND)
    add_executable(java_process_detector tests/java/linux/java_process_detector.cpp)
    target_link_libraries(java_process_detector PRIVATE dl)
endif()

# 테스트 타깃에도 PCH 적용
set(TEST_TARGETS
    demo_target
    aes_lib_test
    symm_aes_gcm_test
    ecc_sign_test
    ecc_ECIES_test
    openssl3_ex2_test
    openssl3_ex2_params_test
    dynamic_analysis_cli)
if(JNI_FOUND)
    list(APPEND TEST_TARGETS java_process_detector)
endif()

foreach(tgt IN LISTS TEST_TARGETS)
  target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
endforeach()

set(OPENSSL_CRYPTO_TARGETS
    aes_lib_test
    symm_aes_gcm_test
    ecc_sign_test
    ecc_ECIES_test
    openssl3_ex2_test
    openssl3_ex2_params_test)

foreach(tgt IN LISTS OPENSSL_CRYPTO_TARGETS)
    target_link_libraries(${tgt} PRIVATE OpenSSL::Crypto)
endforeach()

# ── 사용 힌트
message(STATUS "Build:  cmake -S . -B build && cmake --build build -j")
message(STATUS "Run:    HOOK_VERBOSE=1 LD_PRELOAD=${CMAKE_BINARY_DIR}/lib/libhook.so ${CMAKE_BINARY_DIR}/bin/aes_lib_test")
