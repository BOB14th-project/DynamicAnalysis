cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES CXX)

# ── 공통 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
add_compile_definitions(_GNU_SOURCE)

# 아웃풋 디렉토리 통일
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# 헤더 경로
include_directories(${CMAKE_SOURCE_DIR}/include)

# OpenSSL (훅/테스트에서 사용)
find_package(OpenSSL REQUIRED)

# ── Hook 라이브러리 소스
set(HOOK_SRCS
    src/init.cpp
    src/log.cpp
    src/resolver.cpp
    src/hooks/foo_hook.cpp
    src/hooks/openssl_hooks.cpp
    src/utils/crypto_utils.cpp    
    src/utils/output.cpp    
)

add_library(hook SHARED ${HOOK_SRCS})
target_precompile_headers(hook PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
target_link_libraries(hook PRIVATE dl pthread OpenSSL::Crypto)

# ── 테스트 실행파일들
add_executable(aes_lib_test   tests/aes_lib_test.cpp)
add_executable(demo_target    tests/demo_target.cpp)
add_executable(ecc_ECIES_test tests/ecc_ECIES_test.cpp)
add_executable(ecc_sign_test  tests/ecc_sign_test.cpp)
add_executable(openssl3_ex2_test tests/openssl3_ex2_test.cpp)

# 테스트 타깃에도 PCH 적용(원치 않으면 삭제)
foreach(tgt IN ITEMS aes_lib_test demo_target ecc_ECIES_test ecc_sign_test openssl3_ex2_test)
  target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
endforeach()

# OpenSSL 필요한 테스트에 링크
target_link_libraries(aes_lib_test   PRIVATE OpenSSL::Crypto)
target_link_libraries(ecc_ECIES_test PRIVATE OpenSSL::Crypto)
target_link_libraries(ecc_sign_test  PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl3_ex2_test PRIVATE OpenSSL::Crypto)  
# demo_target이 OpenSSL을 안 쓰면 아래 줄은 유지하지 않아도 됨
# target_link_libraries(demo_target    PRIVATE OpenSSL::Crypto)

# ── 사용 힌트
message(STATUS "Build:  cmake -S . -B build && cmake --build build -j")
message(STATUS "Run:    HOOK_VERBOSE=1 LD_PRELOAD=${CMAKE_BINARY_DIR}/libhook.so ${CMAKE_BINARY_DIR}/aes_lib_test")
