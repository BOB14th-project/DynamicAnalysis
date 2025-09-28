cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES C CXX)

include(CheckIncludeFile)

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
option(ENABLE_LIBSODIUM   "Build libsodium hooks"                           ON)
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

    if(ENABLE_LIBSODIUM)
        list(APPEND HOOK_SRCS src/Linux/hooks/hook_libsodium.cpp)
    endif()

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
add_executable(openssl_aes_lib_test                 tests/openssl/symmetric/openssl_aes_lib_test.cpp)
add_executable(openssl_symm_aes_gcm_test            tests/openssl/aead/openssl_symm_aes_gcm_test.cpp)
add_executable(openssl_ecc_sign_test                tests/openssl/ecc/openssl_ecc_sign_test.cpp)
add_executable(openssl_ecc_ecies_test               tests/openssl/ecc/openssl_ecc_ecies_test.cpp)
add_executable(openssl_provider_ex2_test            tests/openssl/provider/openssl_provider_ex2_test.cpp)
add_executable(openssl_provider_ex2_params_test     tests/openssl/provider/openssl_provider_ex2_params_test.cpp)

# ── libsodium 테스트 (선택적)
set(LIBSODIUM_FOUND OFF)
if(ENABLE_LIBSODIUM)
    find_path(LIBSODIUM_INCLUDE_DIR sodium.h)
    find_library(LIBSODIUM_LIBRARY sodium)
    if(LIBSODIUM_INCLUDE_DIR AND LIBSODIUM_LIBRARY)
        set(LIBSODIUM_FOUND ON)
        add_executable(libsodium_chacha20_poly1305_demo tests/libsodium/aead/chacha20_poly1305_demo.c)
        target_include_directories(libsodium_chacha20_poly1305_demo PRIVATE ${LIBSODIUM_INCLUDE_DIR})
        target_link_libraries(libsodium_chacha20_poly1305_demo PRIVATE ${LIBSODIUM_LIBRARY})

        add_executable(libsodium_xchacha20_poly1305_demo tests/libsodium/aead/xchacha20_poly1305_demo.c)
        target_include_directories(libsodium_xchacha20_poly1305_demo PRIVATE ${LIBSODIUM_INCLUDE_DIR})
        target_link_libraries(libsodium_xchacha20_poly1305_demo PRIVATE ${LIBSODIUM_LIBRARY})

        add_executable(libsodium_secretbox_demo tests/libsodium/secretbox/libsodium_secretbox_demo.c)
        target_include_directories(libsodium_secretbox_demo PRIVATE ${LIBSODIUM_INCLUDE_DIR})
        target_link_libraries(libsodium_secretbox_demo PRIVATE ${LIBSODIUM_LIBRARY})

        add_executable(libsodium_box_demo tests/libsodium/box/libsodium_box_demo.c)
        target_include_directories(libsodium_box_demo PRIVATE ${LIBSODIUM_INCLUDE_DIR})
        target_link_libraries(libsodium_box_demo PRIVATE ${LIBSODIUM_LIBRARY})

        add_executable(libsodium_sign_demo tests/libsodium/sign/libsodium_sign_demo.c)
        target_include_directories(libsodium_sign_demo PRIVATE ${LIBSODIUM_INCLUDE_DIR})
        target_link_libraries(libsodium_sign_demo PRIVATE ${LIBSODIUM_LIBRARY})
    else()
        message(WARNING "libsodium headers or library not found; skipping libsodium demo build")
    endif()
endif()

if(ENABLE_AF_ALG)
    check_include_file("linux/if_alg.h" HAVE_LINUX_IF_ALG_H)
    if(HAVE_LINUX_IF_ALG_H)
        add_executable(af_alg_skcipher_aes_cbc_demo tests/af_alg/af_alg_skcipher_aes_cbc_demo.c)
        add_executable(af_alg_aes_gcm_demo tests/af_alg/af_alg_aes_gcm_demo.c)
        add_executable(af_alg_hmac_sha256_demo tests/af_alg/af_alg_hmac_sha256_demo.c)
    else()
        message(WARNING "linux/if_alg.h not found; skipping AF_ALG demo build")
    endif()
endif()

if(ENABLE_CRYPTODEV)
    check_include_file("crypto/cryptodev.h" HAVE_CRYPTODEV_H)
    if(HAVE_CRYPTODEV_H)
        add_executable(cryptodev_aes_cbc_demo tests/cryptodev/ioctl/cryptodev_aes_cbc_demo.c)
        add_executable(cryptodev_hmac_sha256_demo tests/cryptodev/ioctl/cryptodev_hmac_sha256_demo.c)
        add_executable(cryptodev_rsa_demo tests/cryptodev/ioctl/cryptodev_rsa_demo.c)
    else()
        message(WARNING "crypto/cryptodev.h not found; skipping cryptodev demo build")
    endif()
endif()

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
    openssl_aes_lib_test
    openssl_symm_aes_gcm_test
    openssl_ecc_sign_test
    openssl_ecc_ecies_test
    openssl_provider_ex2_test
    openssl_provider_ex2_params_test
    dynamic_analysis_cli)
if(JNI_FOUND)
    list(APPEND TEST_TARGETS java_process_detector)
endif()
if(LIBSODIUM_FOUND)
    list(APPEND TEST_TARGETS
        libsodium_chacha20_poly1305_demo
        libsodium_xchacha20_poly1305_demo
        libsodium_secretbox_demo
        libsodium_box_demo
        libsodium_sign_demo)
endif()
if(ENABLE_AF_ALG AND HAVE_LINUX_IF_ALG_H)
    list(APPEND TEST_TARGETS
        af_alg_skcipher_aes_cbc_demo
        af_alg_aes_gcm_demo
        af_alg_hmac_sha256_demo)
endif()
if(ENABLE_CRYPTODEV AND HAVE_CRYPTODEV_H)
    list(APPEND TEST_TARGETS
        cryptodev_aes_cbc_demo
        cryptodev_hmac_sha256_demo
        cryptodev_rsa_demo)
endif()

foreach(tgt IN LISTS TEST_TARGETS)
  if(NOT tgt STREQUAL "libsodium_chacha20_poly1305_demo" AND
     NOT tgt STREQUAL "libsodium_xchacha20_poly1305_demo" AND
     NOT tgt STREQUAL "libsodium_secretbox_demo" AND
     NOT tgt STREQUAL "libsodium_box_demo" AND
     NOT tgt STREQUAL "libsodium_sign_demo" AND
     NOT tgt STREQUAL "af_alg_skcipher_aes_cbc_demo" AND
     NOT tgt STREQUAL "af_alg_aes_gcm_demo" AND
     NOT tgt STREQUAL "af_alg_hmac_sha256_demo" AND
     NOT tgt STREQUAL "cryptodev_aes_cbc_demo" AND
     NOT tgt STREQUAL "cryptodev_hmac_sha256_demo" AND
     NOT tgt STREQUAL "cryptodev_rsa_demo")
    target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/pch.h)
  endif()
endforeach()

set(OPENSSL_CRYPTO_TARGETS
    openssl_aes_lib_test
    openssl_symm_aes_gcm_test
    openssl_ecc_sign_test
    openssl_ecc_ecies_test
    openssl_provider_ex2_test
    openssl_provider_ex2_params_test)

foreach(tgt IN LISTS OPENSSL_CRYPTO_TARGETS)
    target_link_libraries(${tgt} PRIVATE OpenSSL::Crypto)
endforeach()

# ── 사용 힌트
message(STATUS "Build:  cmake -S . -B build && cmake --build build -j")
message(STATUS "Run:    HOOK_VERBOSE=1 LD_PRELOAD=${CMAKE_BINARY_DIR}/lib/libhook.so ${CMAKE_BINARY_DIR}/bin/openssl_aes_lib_test")
