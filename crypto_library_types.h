/**
 * @file crypto_library_types.h
 * @brief 정적 분석을 통해 탐지할 수 있는 암호화 라이브러리 타입 정의
 * @version 1.0
 * @date 2025
 * 
 * 사용 빈도와 중요도를 기반으로 우선순위가 부여된 암호화 라이브러리 열거형
 */

#ifndef CRYPTO_LIBRARY_TYPES_H
#define CRYPTO_LIBRARY_TYPES_H

#include <stdint.h>

/**
 * @brief 암호화 라이브러리 카테고리
 * 플랫폼과 언어별로 분류
 */
typedef enum {
    CRYPTO_CATEGORY_C_CPP = 0,           // C/C++ 네이티브 라이브러리
    CRYPTO_CATEGORY_OS_NATIVE,           // 운영체제 내장 API
    CRYPTO_CATEGORY_PYTHON,              // Python 전용 라이브러리
    CRYPTO_CATEGORY_JAVA_ANDROID,        // Java/Android 라이브러리
    CRYPTO_CATEGORY_JAVASCRIPT,          // JavaScript/Node.js 라이브러리
    CRYPTO_CATEGORY_RUST,                // Rust 전용 라이브러리
    CRYPTO_CATEGORY_GO,                  // Go 전용 라이브러리
    CRYPTO_CATEGORY_OTHER,               // 기타 언어/플랫폼
    CRYPTO_CATEGORY_UNKNOWN = 0xFF       // 미확인 카테고리
} crypto_library_category_t;

/**
 * @brief 암호화 라이브러리 타입
 * 사용 빈도와 중요도 순으로 정렬 (높은 우선순위 = 낮은 값)
 */
typedef enum {
    // === C/C++ 라이브러리 (0x0000 - 0x00FF) ===
    // 최고 우선순위: 업계 표준
    CRYPTO_LIB_OPENSSL          = 0x0001,   // 👑 사실상 업계 표준, 최우선
    CRYPTO_LIB_LIBSSL           = 0x0002,   // OpenSSL의 SSL/TLS 부분
    CRYPTO_LIB_LIBCRYPTO        = 0x0003,   // OpenSSL의 암호화 부분
    
    // 고 우선순위: 주요 파생/대체재
    CRYPTO_LIB_BORINGSSL        = 0x0010,   // Google 버전 (Android, Chrome)
    CRYPTO_LIB_LIBRESSL         = 0x0011,   // OpenBSD 버전
    CRYPTO_LIB_MBEDTLS          = 0x0012,   // IoT/임베디드 표준
    CRYPTO_LIB_LIBSODIUM        = 0x0013,   // 현대적 API 설계
    
    // 중 우선순위: 특수 목적/레거시
    CRYPTO_LIB_CRYPTOPP         = 0x0020,   // C++ 전용 라이브러리
    CRYPTO_LIB_GNUTLS           = 0x0021,   // GNU TLS 구현
    CRYPTO_LIB_LIBGCRYPT        = 0x0022,   // GNU 암호화 라이브러리
    CRYPTO_LIB_WOLFSSL          = 0x0023,   // 임베디드/IoT 특화
    CRYPTO_LIB_BEARSSL          = 0x0024,   // 경량 SSL/TLS
    
    // === 운영체제 내장 API (0x0100 - 0x01FF) ===
    // Windows
    CRYPTO_LIB_WIN_CNG          = 0x0101,   // 💻 Windows CNG (bcrypt.dll)
    CRYPTO_LIB_WIN_CRYPTOAPI    = 0x0102,   // Windows 레거시 CryptoAPI
    CRYPTO_LIB_WIN_BCRYPT       = 0x0103,   // bcrypt.dll
    CRYPTO_LIB_WIN_NCRYPT       = 0x0104,   // ncrypt.dll
    CRYPTO_LIB_WIN_CRYPT32      = 0x0105,   // crypt32.dll
    
    // Linux/Unix
    CRYPTO_LIB_LINUX_KERNEL     = 0x0110,   // Linux Kernel Crypto API
    CRYPTO_LIB_LINUX_KEYRING    = 0x0111,   // Linux Keyring API
    
    // macOS
    CRYPTO_LIB_MACOS_SECURITY   = 0x0120,   // macOS Security Framework
    CRYPTO_LIB_MACOS_COMMONCRYPTO = 0x0121, // macOS CommonCrypto
    
    // === Python 라이브러리 (0x0200 - 0x02FF) ===
    CRYPTO_LIB_PY_CRYPTOGRAPHY  = 0x0201,   // 🐍 Python 표준
    CRYPTO_LIB_PY_CRYPTODOME    = 0x0202,   // 순수 Python 구현
    CRYPTO_LIB_PY_M2CRYPTO      = 0x0203,   // OpenSSL 래퍼
    CRYPTO_LIB_PY_PYCRYPTO      = 0x0204,   // 레거시 (deprecated)
    CRYPTO_LIB_PY_HASHLIB       = 0x0205,   // Python 내장 해시
    
    // === Java/Android 라이브러리 (0x0300 - 0x03FF) ===
    CRYPTO_LIB_JAVA_JCA         = 0x0301,   // ☕ Java 표준 아키텍처
    CRYPTO_LIB_JAVA_JCE         = 0x0302,   // Java Cryptography Extension
    CRYPTO_LIB_BOUNCY_CASTLE    = 0x0303,   // Java 사실상 표준
    CRYPTO_LIB_GOOGLE_TINK      = 0x0304,   // Google 안전 API
    CRYPTO_LIB_ANDROID_KEYSTORE = 0x0305,   // Android 키스토어
    CRYPTO_LIB_CONSCRYPT        = 0x0306,   // Android OpenSSL 제공자
    
    // === JavaScript/Node.js 라이브러리 (0x0400 - 0x04FF) ===
    CRYPTO_LIB_WEB_CRYPTO_API   = 0x0401,   // 🌐 브라우저 표준
    CRYPTO_LIB_NODEJS_CRYPTO    = 0x0402,   // Node.js 내장 모듈
    CRYPTO_LIB_CRYPTOJS         = 0x0403,   // 순수 JavaScript
    CRYPTO_LIB_SUBTLE_CRYPTO    = 0x0404,   // Web Crypto API 구현체
    CRYPTO_LIB_FORGE            = 0x0405,   // JavaScript 암호화 툴킷
    
    // === Rust 라이브러리 (0x0500 - 0x05FF) ===
    CRYPTO_LIB_RUST_RING        = 0x0501,   // Rust 표준
    CRYPTO_LIB_RUST_CRYPTO      = 0x0502,   // RustCrypto 프로젝트
    CRYPTO_LIB_RUST_OPENSSL     = 0x0503,   // Rust OpenSSL 바인딩
    CRYPTO_LIB_RUST_SODIUM      = 0x0504,   // Rust Sodium 바인딩
    
    // === Go 라이브러리 (0x0600 - 0x06FF) ===
    CRYPTO_LIB_GO_CRYPTO        = 0x0601,   // Go 표준 패키지
    CRYPTO_LIB_GO_TLS           = 0x0602,   // Go TLS 구현
    CRYPTO_LIB_GO_X509          = 0x0603,   // Go X.509 구현
    
    // === 기타 언어/플랫폼 (0x0700 - 0x0EFF) ===
    // .NET
    CRYPTO_LIB_DOTNET_CRYPTO    = 0x0701,   // .NET Cryptography
    CRYPTO_LIB_DOTNET_SECURITY  = 0x0702,   // .NET Security
    
    // PHP
    CRYPTO_LIB_PHP_OPENSSL      = 0x0710,   // PHP OpenSSL 확장
    CRYPTO_LIB_PHP_MCRYPT       = 0x0711,   // PHP mcrypt (deprecated)
    CRYPTO_LIB_PHP_SODIUM       = 0x0712,   // PHP Sodium 확장
    
    // Ruby
    CRYPTO_LIB_RUBY_OPENSSL     = 0x0720,   // Ruby OpenSSL 바인딩
    
    // Swift
    CRYPTO_LIB_SWIFT_CRYPTO     = 0x0730,   // Swift Crypto
    
    // 하드웨어/펌웨어
    CRYPTO_LIB_HARDWARE_HSM     = 0x0800,   // Hardware Security Module
    CRYPTO_LIB_TPM              = 0x0801,   // Trusted Platform Module
    CRYPTO_LIB_ARM_TRUSTZONE    = 0x0802,   // ARM TrustZone
    
    // === 특수/실험적 (0x0F00 - 0x0FFF) ===
    CRYPTO_LIB_EXPERIMENTAL     = 0x0F00,   // 실험적 구현체
    CRYPTO_LIB_CUSTOM           = 0x0F01,   // 커스텀 구현체
    
    // === 오류/미정의 (0xFF00 - 0xFFFF) ===
    CRYPTO_LIB_UNKNOWN          = 0xFF00,   // 알 수 없는 라이브러리
    CRYPTO_LIB_ERROR            = 0xFFFF    // 탐지 오류
} crypto_library_type_t;

/**
 * @brief 암호화 라이브러리 우선순위 레벨
 * 동적 분석 에이전트 선택 시 사용
 */
typedef enum {
    CRYPTO_PRIORITY_CRITICAL    = 1,        // 최우선 (OpenSSL, Windows CNG 등)
    CRYPTO_PRIORITY_HIGH        = 2,        // 고우선순위 (BoringSSL, mbedTLS 등)
    CRYPTO_PRIORITY_MEDIUM      = 3,        // 중우선순위 (특수 목적 라이브러리)
    CRYPTO_PRIORITY_LOW         = 4,        // 저우선순위 (레거시, 실험적)
    CRYPTO_PRIORITY_IGNORE      = 5         // 무시 (오류, 미확인)
} crypto_library_priority_t;

/**
 * @brief 암호화 라이브러리 정보 구조체
 */
typedef struct {
    crypto_library_type_t type;             // 라이브러리 타입
    crypto_library_category_t category;     // 카테고리
    crypto_library_priority_t priority;     // 우선순위
    const char* name;                       // 라이브러리 이름
    const char* agent_file;                 // 대응하는 에이전트 파일
    const char* description;                // 설명
} crypto_library_info_t;

/**
 * @brief 정적 분석 결과 구조체
 */
typedef struct {
    crypto_library_type_t detected_libraries[32];  // 탐지된 라이브러리 배열
    size_t library_count;                          // 탐지된 라이브러리 수
    crypto_library_type_t primary_library;        // 주요 라이브러리 (최고 우선순위)
    const char* binary_path;                       // 분석 대상 바이너리 경로
    const char* platform;                          // 플랫폼 (linux/windows/macos)
    const char* architecture;                      // 아키텍처 (x64/x86/arm64)
} static_analysis_result_t;

// === 함수 선언 ===

/**
 * @brief 라이브러리 타입의 우선순위 반환
 * @param type 라이브러리 타입
 * @return 우선순위 레벨
 */
crypto_library_priority_t get_library_priority(crypto_library_type_t type);

/**
 * @brief 라이브러리 타입의 카테고리 반환
 * @param type 라이브러리 타입
 * @return 카테고리
 */
crypto_library_category_t get_library_category(crypto_library_type_t type);

/**
 * @brief 라이브러리 타입에 대응하는 에이전트 파일명 반환
 * @param type 라이브러리 타입
 * @return 에이전트 파일명 (NULL if not found)
 */
const char* get_agent_filename(crypto_library_type_t type);

/**
 * @brief 라이브러리 이름 문자열로부터 타입 반환
 * @param library_name 라이브러리 이름 (예: "libssl.so.1.1")
 * @return 라이브러리 타입
 */
crypto_library_type_t detect_library_type(const char* library_name);

/**
 * @brief 정적 분석 결과에서 주요 라이브러리 선택
 * @param result 정적 분석 결과
 * @return 선택된 주요 라이브러리 타입
 */
crypto_library_type_t select_primary_library(const static_analysis_result_t* result);

/**
 * @brief 라이브러리 타입을 문자열로 변환
 * @param type 라이브러리 타입
 * @return 라이브러리 이름 문자열
 */
const char* crypto_library_type_to_string(crypto_library_type_t type);

// === 함수 구현 (인라인) ===

/**
 * @brief 라이브러리 타입을 문자열로 변환
 */
inline const char* crypto_library_type_to_string(crypto_library_type_t type) {
    switch (type) {
        // C/C++ 라이브러리
        case CRYPTO_LIB_OPENSSL:          return "OpenSSL";
        case CRYPTO_LIB_LIBSSL:           return "LibSSL";
        case CRYPTO_LIB_LIBCRYPTO:        return "LibCrypto";
        case CRYPTO_LIB_BORINGSSL:        return "BoringSSL";
        case CRYPTO_LIB_LIBRESSL:         return "LibreSSL";
        case CRYPTO_LIB_MBEDTLS:          return "mbedTLS";
        case CRYPTO_LIB_LIBSODIUM:        return "libsodium";
        case CRYPTO_LIB_CRYPTOPP:         return "Crypto++";
        case CRYPTO_LIB_GNUTLS:           return "GnuTLS";
        case CRYPTO_LIB_LIBGCRYPT:        return "libgcrypt";
        case CRYPTO_LIB_WOLFSSL:          return "WolfSSL";
        case CRYPTO_LIB_BEARSSL:          return "BearSSL";
        
        // Windows API
        case CRYPTO_LIB_WIN_CNG:          return "Windows CNG";
        case CRYPTO_LIB_WIN_CRYPTOAPI:    return "Windows CryptoAPI";
        case CRYPTO_LIB_WIN_BCRYPT:       return "Windows BCrypt";
        case CRYPTO_LIB_WIN_NCRYPT:       return "Windows NCrypt";
        case CRYPTO_LIB_WIN_CRYPT32:      return "Windows Crypt32";
        
        // Linux/Unix
        case CRYPTO_LIB_LINUX_KERNEL:     return "Linux Kernel Crypto";
        case CRYPTO_LIB_LINUX_KEYRING:    return "Linux Keyring";
        
        // macOS
        case CRYPTO_LIB_MACOS_SECURITY:   return "macOS Security Framework";
        case CRYPTO_LIB_MACOS_COMMONCRYPTO: return "macOS CommonCrypto";
        
        // Python
        case CRYPTO_LIB_PY_CRYPTOGRAPHY:  return "Python cryptography";
        case CRYPTO_LIB_PY_CRYPTODOME:    return "Python pycryptodome";
        case CRYPTO_LIB_PY_M2CRYPTO:      return "Python M2Crypto";
        case CRYPTO_LIB_PY_PYCRYPTO:      return "Python pycrypto";
        case CRYPTO_LIB_PY_HASHLIB:       return "Python hashlib";
        
        // Java/Android
        case CRYPTO_LIB_JAVA_JCA:         return "Java JCA";
        case CRYPTO_LIB_JAVA_JCE:         return "Java JCE";
        case CRYPTO_LIB_BOUNCY_CASTLE:    return "Bouncy Castle";
        case CRYPTO_LIB_GOOGLE_TINK:      return "Google Tink";
        case CRYPTO_LIB_ANDROID_KEYSTORE: return "Android Keystore";
        case CRYPTO_LIB_CONSCRYPT:        return "Conscrypt";
        
        // JavaScript/Node.js
        case CRYPTO_LIB_WEB_CRYPTO_API:   return "Web Crypto API";
        case CRYPTO_LIB_NODEJS_CRYPTO:    return "Node.js crypto";
        case CRYPTO_LIB_CRYPTOJS:         return "CryptoJS";
        case CRYPTO_LIB_SUBTLE_CRYPTO:    return "SubtleCrypto";
        case CRYPTO_LIB_FORGE:            return "node-forge";
        
        // Rust
        case CRYPTO_LIB_RUST_RING:        return "Rust ring";
        case CRYPTO_LIB_RUST_CRYPTO:      return "RustCrypto";
        case CRYPTO_LIB_RUST_OPENSSL:     return "Rust OpenSSL";
        case CRYPTO_LIB_RUST_SODIUM:      return "Rust Sodium";
        
        // Go
        case CRYPTO_LIB_GO_CRYPTO:        return "Go crypto";
        case CRYPTO_LIB_GO_TLS:           return "Go TLS";
        case CRYPTO_LIB_GO_X509:          return "Go X509";
        
        // 기타
        case CRYPTO_LIB_DOTNET_CRYPTO:    return ".NET Cryptography";
        case CRYPTO_LIB_DOTNET_SECURITY:  return ".NET Security";
        case CRYPTO_LIB_PHP_OPENSSL:      return "PHP OpenSSL";
        case CRYPTO_LIB_PHP_MCRYPT:       return "PHP mcrypt";
        case CRYPTO_LIB_PHP_SODIUM:       return "PHP Sodium";
        case CRYPTO_LIB_RUBY_OPENSSL:     return "Ruby OpenSSL";
        case CRYPTO_LIB_SWIFT_CRYPTO:     return "Swift Crypto";
        
        // 하드웨어
        case CRYPTO_LIB_HARDWARE_HSM:     return "Hardware HSM";
        case CRYPTO_LIB_TPM:              return "TPM";
        case CRYPTO_LIB_ARM_TRUSTZONE:    return "ARM TrustZone";
        
        // 특수/실험적
        case CRYPTO_LIB_EXPERIMENTAL:     return "Experimental";
        case CRYPTO_LIB_CUSTOM:           return "Custom";
        
        // 오류/미정의
        case CRYPTO_LIB_UNKNOWN:          return "Unknown";
        case CRYPTO_LIB_ERROR:            return "Error";
        
        default:                          return "Undefined";
    }
}

#endif // CRYPTO_LIBRARY_TYPES_H