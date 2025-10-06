cmake_minimum_required(VERSION 3.16)
project(ldpreload_hook LANGUAGES C CXX)

include(CheckIncludeFile)

# TODO: update target source lists to new src/common and src/platform layout
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
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/common
    ${CMAKE_SOURCE_DIR}/include/platform
    ${CMAKE_SOURCE_DIR}/include/platform/linux
    ${CMAKE_SOURCE_DIR}/include/platform/windows
)

# OpenSSL 필요 (openssl 훅/테스트)
find_package(OpenSSL REQUIRED)

# ── 빌드 옵션
option(ENABLE_AF_ALG      "Build AF_ALG hook (Linux kernel crypto sockets)" ON)
option(ENABLE_CRYPTODEV   "Build cryptodev hook (ioctl-based)"              OFF)
option(ENABLE_LIBSODIUM   "Build libsodium hooks"                           ON)
option(ENABLE_MBEDTLS     "Build mbedTLS demos"                             ON)
option(HOOK_VERBOSE       "Verbose logging inside hooks"                    OFF)
option(HOOK_MASK          "Mask key/iv/tag in NDJSON (hash/trunc)"          OFF)

if(MSVC)
    add_compile_options(/utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

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

# ── Platform-specific hook sources
if(WIN32)
    set(HOOK_SRCS
        src/platform/windows/core/windows_hook_dll.cpp
        src/platform/windows/hooks/hook_openssl_detours.cpp
        src/platform/windows/hooks/hook_openssl_state.cpp
        src/platform/windows/utils/output.cpp
        src/platform/windows/utils/crypto_utils.cpp
    )

    # Windows-specific libraries
    find_package(detours QUIET)
    if(NOT detours_FOUND)
        message(STATUS "Detours not found via find_package, trying manual detection...")
        find_path(DETOURS_INCLUDE_DIR detours.h
                  PATHS "C:/Program Files/Microsoft Research/Detours/include"
                        "C:/dev/detours/include"
                        "$ENV{DETOURS_ROOT}/include")
        find_library(DETOURS_LIBRARY detours
                     PATHS "C:/Program Files/Microsoft Research/Detours/lib.X64"
                           "C:/dev/detours/lib.X64"
                           "$ENV{DETOURS_ROOT}/lib.X64")
        if(DETOURS_INCLUDE_DIR AND DETOURS_LIBRARY)
            set(detours_FOUND TRUE)
            message(STATUS "Found Detours: ${DETOURS_INCLUDE_DIR}")
        endif()
    endif()
elseif(UNIX)
    set(HOOK_SRCS
        src/platform/linux/core/init.cpp
        src/platform/linux/core/log.cpp
        src/platform/linux/core/resolver.cpp
        src/platform/linux/utils/output.cpp
        src/platform/linux/utils/crypto_utils.cpp
        src/platform/linux/utils/elf_analyzer.cpp
        src/platform/linux/hooks/hook_openssl_core.cpp
        src/platform/linux/hooks/hook_openssl_provider.cpp
        src/platform/linux/hooks/hook_openssl_ecc.cpp
        src/platform/linux/hooks/hook_openssl_state.cpp
        src/platform/linux/hooks/hook_pycryptodome.cpp
    )

    if(ENABLE_LIBSODIUM)
        list(APPEND HOOK_SRCS src/platform/linux/hooks/hook_libsodium.cpp)
    endif()

    if(ENABLE_AF_ALG)
        list(APPEND HOOK_SRCS src/platform/linux/hooks/hook_af_alg.cpp)
    endif()

    if(ENABLE_CRYPTODEV)
        list(APPEND HOOK_SRCS src/platform/linux/hooks/hook_cryptodev.cpp)
    endif()

    if(JNI_FOUND)
        list(APPEND HOOK_SRCS
            src/platform/linux/hooks/hook_jni.cpp
            src/platform/linux/hooks/hook_java_native_crypto.cpp
            src/platform/linux/utils/java_crypto_utils.cpp
        )
    endif()
else()
    message(WARNING "Non-Linux builds currently include only platform-agnostic sources")
endif()

add_library(hook SHARED ${HOOK_SRCS})
target_precompile_headers(hook PRIVATE ${CMAKE_SOURCE_DIR}/include/common/pch.h)

# Platform-specific compilation and linking
if(WIN32)
    # Windows-specific compile options
    target_compile_options(hook PRIVATE /O2 /W3 /EHsc)
    target_compile_definitions(hook PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

    # Windows-specific libraries
    target_link_libraries(hook PRIVATE OpenSSL::Crypto)

    if(detours_FOUND)
        if(DETOURS_INCLUDE_DIR)
            target_include_directories(hook PRIVATE ${DETOURS_INCLUDE_DIR})
        endif()
        if(DETOURS_LIBRARY)
            target_link_libraries(hook PRIVATE ${DETOURS_LIBRARY})
        else()
            target_link_libraries(hook PRIVATE detours)
        endif()
    else()
        message(FATAL_ERROR "Detours library is required for Windows builds but was not found")
    endif()
else()
    # Linux-specific compile options
    target_compile_options(hook PRIVATE -O2 -fPIC -fno-omit-frame-pointer -Wall -Wextra)
    target_link_libraries(hook PRIVATE dl pthread OpenSSL::Crypto)
endif()

# Java 지원이 가능한 경우 JNI 라이브러리 링크
if(JNI_FOUND)
    target_link_libraries(hook PRIVATE ${JNI_LIBRARIES})
endif()

# ── OpenSSL 테스트 (암호화 경로별 커버리지) - 크로스 플랫폼
add_executable(openssl_aes_lib_test                 tests/openssl/symmetric/openssl_aes_lib_test.cpp)
add_executable(openssl_symm_aes_gcm_test            tests/openssl/aead/openssl_symm_aes_gcm_test.cpp)
add_executable(openssl_ecc_sign_test                tests/openssl/ecc/openssl_ecc_sign_test.cpp)
add_executable(openssl_ecc_ecies_test               tests/openssl/ecc/openssl_ecc_ecies_test.cpp)
add_executable(openssl_provider_ex2_test            tests/openssl/provider/openssl_provider_ex2_test.cpp)
add_executable(openssl_provider_ex2_params_test     tests/openssl/provider/openssl_provider_ex2_params_test.cpp)

# 모든 OpenSSL 테스트는 크로스 플랫폼으로 OpenSSL::Crypto 링크
target_link_libraries(openssl_aes_lib_test PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl_symm_aes_gcm_test PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl_ecc_sign_test PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl_ecc_ecies_test PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl_provider_ex2_test PRIVATE OpenSSL::Crypto)
target_link_libraries(openssl_provider_ex2_params_test PRIVATE OpenSSL::Crypto)

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

set(GNUTLS_FOUND OFF)
find_path(GNUTLS_INCLUDE_DIR gnutls/crypto.h)
find_library(GNUTLS_LIBRARY gnutls)
if(GNUTLS_INCLUDE_DIR AND GNUTLS_LIBRARY)
    set(GNUTLS_FOUND ON)
    include_directories(${GNUTLS_INCLUDE_DIR})
    target_sources(hook PRIVATE src/platform/linux/hooks/hook_gnutls.cpp)
    add_executable(gnutls_aes_gcm_demo tests/GnuTLS/symmetric/gnutls_aes_gcm_demo.c)
    target_include_directories(gnutls_aes_gcm_demo PRIVATE ${GNUTLS_INCLUDE_DIR})
    target_link_libraries(gnutls_aes_gcm_demo PRIVATE ${GNUTLS_LIBRARY})

    add_executable(gnutls_aes_gcm_roundtrip_demo tests/GnuTLS/symmetric/gnutls_aes_gcm_roundtrip_demo.c)
    target_include_directories(gnutls_aes_gcm_roundtrip_demo PRIVATE ${GNUTLS_INCLUDE_DIR})
    target_link_libraries(gnutls_aes_gcm_roundtrip_demo PRIVATE ${GNUTLS_LIBRARY})

    add_executable(gnutls_aes_cbc_demo tests/GnuTLS/symmetric/gnutls_aes_cbc_demo.c)
    target_include_directories(gnutls_aes_cbc_demo PRIVATE ${GNUTLS_INCLUDE_DIR})
    target_link_libraries(gnutls_aes_cbc_demo PRIVATE ${GNUTLS_LIBRARY})
else()
    message(WARNING "GnuTLS headers or library not found; skipping gnutls demo build")
endif()

set(NSS_FOUND OFF)
find_path(NSS_INCLUDE_DIR NAMES nss.h PATH_SUFFIXES nss)
find_path(NSPR_INCLUDE_DIR NAMES prio.h PATH_SUFFIXES nspr nspr4)
find_path(P11KIT_INCLUDE_DIR NAMES p11-kit/pkcs11.h PATH_SUFFIXES p11-kit p11-kit-1)
find_library(NSS3_LIBRARY nss3)
find_library(NSPR4_LIBRARY nspr4)
find_library(PLDS4_LIBRARY plds4)
find_library(PLC4_LIBRARY plc4)
if(NSS_INCLUDE_DIR AND NSPR_INCLUDE_DIR AND P11KIT_INCLUDE_DIR AND NSS3_LIBRARY AND NSPR4_LIBRARY AND PLDS4_LIBRARY AND PLC4_LIBRARY)
    set(NSS_FOUND ON)
    include_directories(${NSS_INCLUDE_DIR} ${NSPR_INCLUDE_DIR} ${P11KIT_INCLUDE_DIR})
    target_sources(hook PRIVATE src/platform/linux/hooks/hook_nss.cpp)
    add_executable(nss_aes_gcm_demo tests/NSS/symmetric/nss_aes_gcm_demo.c)
    target_include_directories(nss_aes_gcm_demo PRIVATE ${NSS_INCLUDE_DIR})
    target_link_libraries(nss_aes_gcm_demo PRIVATE ${NSS3_LIBRARY} ${NSPR4_LIBRARY} ${PLDS4_LIBRARY} ${PLC4_LIBRARY})

    add_executable(nss_aes_gcm_roundtrip_demo tests/NSS/symmetric/nss_aes_gcm_roundtrip_demo.c)
    target_include_directories(nss_aes_gcm_roundtrip_demo PRIVATE ${NSS_INCLUDE_DIR})
    target_link_libraries(nss_aes_gcm_roundtrip_demo PRIVATE ${NSS3_LIBRARY} ${NSPR4_LIBRARY} ${PLDS4_LIBRARY} ${PLC4_LIBRARY})

    add_executable(nss_aes_cbc_demo tests/NSS/symmetric/nss_aes_cbc_demo.c)
    target_include_directories(nss_aes_cbc_demo PRIVATE ${NSS_INCLUDE_DIR})
    target_link_libraries(nss_aes_cbc_demo PRIVATE ${NSS3_LIBRARY} ${NSPR4_LIBRARY} ${PLDS4_LIBRARY} ${PLC4_LIBRARY})
else()
    message(WARNING "NSS headers or libraries not found; skipping NSS demo build")
endif()

set(MBEDTLS_FOUND OFF)
if(ENABLE_MBEDTLS)
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/gcm.h)
    find_library(MBEDTLS_CRYPTO_LIBRARY mbedcrypto)
    find_library(MBEDTLS_TLS_LIBRARY mbedtls)
    find_library(MBEDTLS_X509_LIBRARY mbedx509)
    if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_CRYPTO_LIBRARY)
        set(MBEDTLS_FOUND ON)
        include_directories(${MBEDTLS_INCLUDE_DIR})
        target_sources(hook PRIVATE src/platform/linux/hooks/hook_mbedtls.cpp)
        add_executable(mbedtls_aes_gcm_demo tests/mbedTLS/symmetric/mbedtls_aes_gcm_demo.c)
        target_link_libraries(mbedtls_aes_gcm_demo PRIVATE ${MBEDTLS_CRYPTO_LIBRARY})

        add_executable(mbedtls_hmac_sha256_demo tests/mbedTLS/hash/mbedtls_hmac_sha256_demo.c)
        target_link_libraries(mbedtls_hmac_sha256_demo PRIVATE ${MBEDTLS_CRYPTO_LIBRARY})

        if(MBEDTLS_TLS_LIBRARY AND MBEDTLS_X509_LIBRARY)
            add_executable(mbedtls_ecdsa_demo tests/mbedTLS/pk/mbedtls_ecdsa_demo.c)
            target_link_libraries(mbedtls_ecdsa_demo PRIVATE ${MBEDTLS_CRYPTO_LIBRARY} ${MBEDTLS_X509_LIBRARY} ${MBEDTLS_TLS_LIBRARY})

            add_executable(mbedtls_rsa_demo tests/mbedTLS/pk/mbedtls_rsa_demo.c)
            target_link_libraries(mbedtls_rsa_demo PRIVATE ${MBEDTLS_CRYPTO_LIBRARY} ${MBEDTLS_X509_LIBRARY} ${MBEDTLS_TLS_LIBRARY})
        else()
            message(WARNING "mbedtls tls/x509 libraries not found; skipping pk demos")
        endif()
    else()
        message(WARNING "mbedTLS headers or library not found; skipping mbedtls demos")
    endif()
endif()

set(WOLFSSL_FOUND OFF)
find_path(WOLFSSL_INCLUDE_DIR wolfssl/wolfcrypt/aes.h)
find_library(WOLFSSL_LIBRARY wolfssl)
if(WOLFSSL_INCLUDE_DIR AND WOLFSSL_LIBRARY)
    set(WOLFSSL_FOUND ON)
    target_sources(hook PRIVATE src/platform/linux/hooks/hook_wolfssl.cpp)
    target_include_directories(hook PRIVATE ${WOLFSSL_INCLUDE_DIR})
    add_executable(wolfssl_aes_gcm_demo tests/wolfSSL/symmetric/wolfssl_aes_gcm_demo.c)
    target_include_directories(wolfssl_aes_gcm_demo PRIVATE ${WOLFSSL_INCLUDE_DIR})
    target_link_libraries(wolfssl_aes_gcm_demo PRIVATE ${WOLFSSL_LIBRARY})

    add_executable(wolfssl_aes_cbc_demo tests/wolfSSL/symmetric/wolfssl_aes_cbc_demo.c)
    target_include_directories(wolfssl_aes_cbc_demo PRIVATE ${WOLFSSL_INCLUDE_DIR})
    target_link_libraries(wolfssl_aes_cbc_demo PRIVATE ${WOLFSSL_LIBRARY})

    add_executable(wolfssl_hmac_sha256_demo tests/wolfSSL/hash/wolfssl_hmac_sha256_demo.c)
    target_include_directories(wolfssl_hmac_sha256_demo PRIVATE ${WOLFSSL_INCLUDE_DIR})
    target_link_libraries(wolfssl_hmac_sha256_demo PRIVATE ${WOLFSSL_LIBRARY})
else()
    message(WARNING "wolfSSL headers or library not found; skipping wolfssl demo build")
endif()

set(BORINGSSL_FOUND OFF)
set(BORINGSSL_INCLUDE_HINTS)
set(BORINGSSL_LIB_HINTS)
if(DEFINED BORINGSSL_ROOT)
    list(APPEND BORINGSSL_INCLUDE_HINTS
        ${BORINGSSL_ROOT}/include
        ${BORINGSSL_ROOT}/include/boringssl
        ${BORINGSSL_ROOT}/src/include)
    list(APPEND BORINGSSL_LIB_HINTS
        ${BORINGSSL_ROOT}/build
        ${BORINGSSL_ROOT}/build/crypto
        ${BORINGSSL_ROOT}/build/lib
        ${BORINGSSL_ROOT}/crypto
        ${BORINGSSL_ROOT}/lib)
endif()

find_path(BORINGSSL_INCLUDE_DIR openssl/is_boringssl.h
          PATHS ${BORINGSSL_INCLUDE_HINTS}
          NO_DEFAULT_PATH)
find_library(BORINGSSL_CRYPTO_LIBRARY crypto
             PATHS ${BORINGSSL_LIB_HINTS}
             NO_DEFAULT_PATH)
if(BORINGSSL_INCLUDE_DIR AND BORINGSSL_CRYPTO_LIBRARY)
    set(BORINGSSL_FOUND ON)
    target_sources(hook PRIVATE src/platform/linux/hooks/hook_boringssl.cpp)
    set_source_files_properties(src/platform/linux/hooks/hook_boringssl.cpp
        PROPERTIES
            COMPILE_FLAGS "-I${BORINGSSL_INCLUDE_DIR}")
    add_executable(boringssl_aes_gcm_demo tests/boringSSL/symmetric/boringssl_aes_gcm_demo.cc)
    target_include_directories(boringssl_aes_gcm_demo PRIVATE ${BORINGSSL_INCLUDE_DIR})
    target_link_libraries(boringssl_aes_gcm_demo PRIVATE ${BORINGSSL_CRYPTO_LIBRARY})

    add_executable(boringssl_aes_gcm_roundtrip_demo tests/boringSSL/symmetric/boringssl_aes_gcm_roundtrip_demo.cc)
    target_include_directories(boringssl_aes_gcm_roundtrip_demo PRIVATE ${BORINGSSL_INCLUDE_DIR})
    target_link_libraries(boringssl_aes_gcm_roundtrip_demo PRIVATE ${BORINGSSL_CRYPTO_LIBRARY})

    add_executable(boringssl_chacha20_poly1305_demo tests/boringSSL/symmetric/boringssl_chacha20_poly1305_demo.cc)
    target_include_directories(boringssl_chacha20_poly1305_demo PRIVATE ${BORINGSSL_INCLUDE_DIR})
    target_link_libraries(boringssl_chacha20_poly1305_demo PRIVATE ${BORINGSSL_CRYPTO_LIBRARY})

    add_executable(boringssl_xchacha20_poly1305_demo tests/boringSSL/symmetric/boringssl_xchacha20_poly1305_demo.cc)
    target_include_directories(boringssl_xchacha20_poly1305_demo PRIVATE ${BORINGSSL_INCLUDE_DIR})
    target_link_libraries(boringssl_xchacha20_poly1305_demo PRIVATE ${BORINGSSL_CRYPTO_LIBRARY})
else()
    message(WARNING "BoringSSL headers or library not found; skipping BoringSSL demo build")
endif()

if(ENABLE_AF_ALG)
    check_include_file("linux/if_alg.h" HAVE_LINUX_IF_ALG_H)
    if(HAVE_LINUX_IF_ALG_H)
        add_executable(af_alg_skcipher_aes_cbc_demo tests/af_alg/af_alg_skcipher_aes_cbc_demo.c)
        add_executable(af_alg_aes_gcm_demo tests/af_alg/af_alg_aes_gcm_demo.c)
        add_executable(af_alg_hmac_sha256_demo tests/af_alg/af_alg_hmac_sha256_demo.c)
        add_executable(af_alg_akcipher_demo tests/af_alg/af_alg_akcipher_demo.c)
    else()
        message(WARNING "linux/if_alg.h not found; skipping AF_ALG demo build")
    endif()
endif()

if(ENABLE_CRYPTODEV)
    # Add local include directory for cryptodev.h
    include_directories(${CMAKE_SOURCE_DIR}/include)
    set(CMAKE_REQUIRED_INCLUDES ${CMAKE_SOURCE_DIR}/include)
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
add_executable(dynamic_analysis_cli src/common/main.cpp src/common/dynamic_analysis.cpp)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "9")
    target_link_libraries(dynamic_analysis_cli PRIVATE stdc++fs)
endif()

# Windows: Add Detours include path for dynamic_analysis_cli
if(WIN32 AND DETOURS_INCLUDE_DIR)
    target_include_directories(dynamic_analysis_cli PRIVATE ${DETOURS_INCLUDE_DIR})
    if(DETOURS_LIBRARY)
        target_link_libraries(dynamic_analysis_cli PRIVATE ${DETOURS_LIBRARY})
    endif()
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
if(GNUTLS_FOUND)
    list(APPEND TEST_TARGETS
        gnutls_aes_gcm_demo
        gnutls_aes_gcm_roundtrip_demo
        gnutls_aes_cbc_demo)
endif()
if(NSS_FOUND)
    list(APPEND TEST_TARGETS
        nss_aes_gcm_demo
        nss_aes_gcm_roundtrip_demo
        nss_aes_cbc_demo)
endif()
if(MBEDTLS_FOUND)
    list(APPEND TEST_TARGETS
        mbedtls_aes_gcm_demo
        mbedtls_hmac_sha256_demo)
    if(TARGET mbedtls_ecdsa_demo)
        list(APPEND TEST_TARGETS mbedtls_ecdsa_demo)
    endif()
    if(TARGET mbedtls_rsa_demo)
        list(APPEND TEST_TARGETS mbedtls_rsa_demo)
    endif()
endif()
if(BORINGSSL_FOUND)
    list(APPEND TEST_TARGETS
        boringssl_aes_gcm_demo
        boringssl_aes_gcm_roundtrip_demo
        boringssl_chacha20_poly1305_demo
        boringssl_xchacha20_poly1305_demo)
endif()
if(ENABLE_AF_ALG AND HAVE_LINUX_IF_ALG_H)
    list(APPEND TEST_TARGETS
        af_alg_skcipher_aes_cbc_demo
        af_alg_aes_gcm_demo
        af_alg_hmac_sha256_demo
        af_alg_akcipher_demo)
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
     NOT tgt STREQUAL "gnutls_aes_gcm_demo" AND
     NOT tgt STREQUAL "gnutls_aes_gcm_roundtrip_demo" AND
     NOT tgt STREQUAL "gnutls_aes_cbc_demo" AND
     NOT tgt STREQUAL "nss_aes_gcm_demo" AND
     NOT tgt STREQUAL "nss_aes_gcm_roundtrip_demo" AND
     NOT tgt STREQUAL "nss_aes_cbc_demo" AND
     NOT tgt STREQUAL "mbedtls_aes_gcm_demo" AND
     NOT tgt STREQUAL "mbedtls_hmac_sha256_demo" AND
     NOT tgt STREQUAL "mbedtls_ecdsa_demo" AND
     NOT tgt STREQUAL "mbedtls_rsa_demo" AND
     NOT tgt STREQUAL "af_alg_skcipher_aes_cbc_demo" AND
     NOT tgt STREQUAL "af_alg_aes_gcm_demo" AND
     NOT tgt STREQUAL "af_alg_hmac_sha256_demo" AND
     NOT tgt STREQUAL "af_alg_akcipher_demo" AND
     NOT tgt STREQUAL "cryptodev_aes_cbc_demo" AND
     NOT tgt STREQUAL "cryptodev_hmac_sha256_demo" AND
     NOT tgt STREQUAL "cryptodev_rsa_demo")
    target_precompile_headers(${tgt} PRIVATE ${CMAKE_SOURCE_DIR}/include/common/pch.h)
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
