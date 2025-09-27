cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES CXX)

# ── 공통 설정
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_definitions(_GNU_SOURCE)

# 아웃풋 디렉토리 통일
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

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

# ── Hook 라이브러리 소스
set(HOOK_SRCS
    src/init.cpp
    src/log.cpp
    src/resolver.cpp
    src/utils/crypto_utils.cpp
    src/utils/output.cpp

    # openssl 훅 (신규)
    src/hooks/hook_openssl_core.cpp
    src/hooks/hook_openssl_provider.cpp
)

# 선택 훅
if(ENABLE_AF_ALG)
  list(APPEND HOOK_SRCS src/hooks/af_alg.cpp)
  add_compile_definitions(ENABLE_AF_ALG=1)
endif()

if(ENABLE_CRYPTODEV)
  list(APPEND HOOK_SRCS src/hooks/cryptodev.cpp)
  add_compile_definitions(ENABLE_CRYPTODEV=1)
endif()

# 주의: 아래 두 파일은 과거/샘플이므로 기본 빌드에서 제외
#   src/hooks/foo_hook.cpp
#   src/hooks/openssl_hooks_old.cpp

# ── Hook 라이브러리 생성
add_library(hook SHARED ${HOOK_SRCS})
target_precompile_headers(hook PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
target_compile_options(hook PRIVATE -O2 -fPIC -fno-omit-frame-pointer -Wall -Wextra)
target_link_libraries(hook PRIVATE dl pthread OpenSSL::Crypto)

# ── 테스트 타깃
# OpenSSL 테스트들
add_executable(aes_lib_test                    tests/openssl_test/aes_lib_test.cpp)
add_executable(demo_target                     tests/openssl_test/demo_target.cpp)
add_executable(ecc_ECIES_test                  tests/openssl_test/ecc_ECIES_test.cpp)
add_executable(ecc_sign_test                   tests/openssl_test/ecc_sign_test.cpp)
add_executable(openssl3_ex2_test               tests/openssl_test/openssl3_ex2_test.cpp)
add_executable(openssl3_ex2_params_test        tests/openssl_test/openssl3_ex2_params_test.cpp)
add_executable(symm_aes_gcm_test               tests/openssl_test/symm_aes_gcm_test.cpp)

# AF_ALG 테스트 (C++)
add_executable(aes_gcm_afalg_test              tests/af_alg_test/aes_gcm_afalg_test.cpp)

# 테스트 타깃에 PCH 적용(원치 않으면 제거)
foreach(tgt IN ITEMS
    aes_lib_test demo_target ecc_ECIES_test ecc_sign_test
    openssl3_ex2_test openssl3_ex2_params_test symm_aes_gcm_test
    aes_gcm_afalg_test)
  target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
endforeach()

# 링크 (OpenSSL 필요한 테스트들)
target_link_libraries(aes_lib_test                 PRIVATE OpenSSL::Crypto)
target_link_libraries(demo_target                  PRIVATE OpenSSL::Crypto)
target_link_libraries(ecc_ECIES_test               PRIVATE OpenSSL::Crypto)
target_link_libraries(ecc_sign_test                PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl3_ex2_test            PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl3_ex2_params_test     PRIVATE OpenSSL::Crypto)
target_link_libraries(symm_aes_gcm_test            PRIVATE OpenSSL::Crypto)
# aes_gcm_afalg_test 는 OpenSSL 불필요

# ── 사용 힌트
message(STATUS "")
message(STATUS "Build:")
message(STATUS "  cmake -S . -B build && cmake --build build -j")
message(STATUS "")
message(STATUS "Run (OpenSSL legacy/provider):")
message(STATUS "  HOOK_NDJSON=$PWD/hook.ndjson LD_BIND_NOW=1 LD_PRELOAD=build/libhook.so build/symm_aes_gcm_test")
message(STATUS "  HOOK_NDJSON=$PWD/hook.ndjson LD_BIND_NOW=1 LD_PRELOAD=build/libhook.so build/openssl3_ex2_params_test")
message(STATUS "")
message(STATUS "Run (AF_ALG):")
message(STATUS "  sudo modprobe algif_aead gcm aes")
message(STATUS "  HOOK_NDJSON=$PWD/hook.ndjson LD_BIND_NOW=1 LD_PRELOAD=build/libhook.so build/aes_gcm_afalg_test")
message(STATUS "")
message(STATUS "Options:")
message(STATUS "  -DENABLE_AF_ALG=OFF, -DENABLE_CRYPTODEV=ON, -DHOOK_VERBOSE=ON, -DHOOK_MASK=ON")
message(STATUS "")
