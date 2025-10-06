// hook_java_native_crypto.cpp - Java 네이티브 암호화 함수 후킹
#include "common/pch.h"

#ifdef JAVA_SUPPORT_ENABLED
#include "platform/linux/java_crypto_utils.h"
#include "platform/linux/resolver.h"
#include "common/hook_common.h"
#include "common/output.h"
#include <dlfcn.h>

// Java Security Provider에서 사용하는 네이티브 함수들
// SunJCE Provider의 네이티브 함수들
typedef void* (*java_aes_encrypt_init_t)(const unsigned char* key, int keylen, const unsigned char* iv);
typedef void* (*java_des_encrypt_init_t)(const unsigned char* key, int keylen, const unsigned char* iv);

// OpenSSL을 사용하는 Java 암호화 라이브러리들
typedef int (*java_evp_cipher_init_t)(void* ctx, const void* cipher, void* engine, 
                                      const unsigned char* key, const unsigned char* iv, int enc);

// Java에서 흔히 사용되는 네이티브 암호화 함수명들
static const char* java_crypto_symbols[] = {
    // SunJCE Provider 관련
    "Java_com_sun_crypto_provider_AESCrypt_implInit",
    "Java_com_sun_crypto_provider_DESCrypt_implInit", 
    "Java_com_sun_crypto_provider_AESCrypt_implEncryptBlock",
    "Java_com_sun_crypto_provider_AESCrypt_implDecryptBlock",
    
    // Bouncy Castle Provider 관련
    "Java_org_bouncycastle_crypto_engines_AESEngine_processBlock",
    "Java_org_bouncycastle_jcajce_provider_symmetric_AES",
    
    // 기타 일반적인 JNI 암호화 함수들
    "Java_*_AES_*",
    "Java_*_DES_*", 
    "Java_*_RSA_*",
    "Java_*_encrypt*",
    "Java_*_decrypt*",
    nullptr
};

// JVM에서 로드된 라이브러리들을 스캔하여 암호화 관련 심볼 찾기
static void scan_loaded_libraries_for_crypto() {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    
    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        // .so 파일만 확인
        if (!strstr(line, ".so")) continue;
        
        // 라이브러리 경로 추출
        char* lib_path = strrchr(line, ' ');
        if (!lib_path) continue;
        lib_path++;
        
        // 개행 문자 제거
        char* newline = strchr(lib_path, '\n');
        if (newline) *newline = '\0';
        
        // Java 관련 라이브러리인지 확인
        if (strstr(lib_path, "java") || strstr(lib_path, "jvm") || 
            strstr(lib_path, "crypto") || strstr(lib_path, "ssl")) {
            
            if (hook_is_verbose()) {
                char log_msg[256];
                int n = snprintf(log_msg, sizeof(log_msg),
                               "[JAVA NATIVE] Scanning library: %s\n", lib_path);
                write(STDERR_FILENO, log_msg, n);
            }
            
            // 라이브러리에서 암호화 심볼 검색
            void* handle = dlopen(lib_path, RTLD_LAZY | RTLD_NOLOAD);
            if (handle) {
                // 여기서 암호화 관련 심볼들을 검색하고 후킹할 수 있음
                dlclose(handle);
            }
        }
    }
    
    fclose(maps);
}

// Java AES 초기화 함수 후킹 (SunJCE Provider)
extern "C" void Java_com_sun_crypto_provider_AESCrypt_implInit(JNIEnv* env, jobject obj, jbyteArray key) {
    if (hook_is_verbose()) {
        write(STDERR_FILENO, "[JAVA HOOK] AESCrypt.implInit called\n", 37);
    }
    
    if (key) {
        jsize keylen = env->GetArrayLength(key);
        jbyte* key_bytes = env->GetByteArrayElements(key, nullptr);
        
        if (key_bytes) {
            char log_msg[128];
            int n = snprintf(log_msg, sizeof(log_msg),
                           "[JAVA HOOK] AES key detected: %d bytes (%d bits)\n", 
                           keylen, keylen * 8);
            write(STDERR_FILENO, log_msg, n);
            
            // 키를 16진수로 출력
            write(STDERR_FILENO, "[JAVA HOOK] AES key: ", 21);
            for (int i = 0; i < keylen; i++) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", (unsigned char)key_bytes[i]);
                write(STDERR_FILENO, hex, 2);
            }
            write(STDERR_FILENO, "\n", 1);
            
            // NDJSON 로그에 기록
            ndjson_log_key_event("java", "Java_AES_init", "java_enc", "AES",
                                 (const uint8_t*)key_bytes, keylen,
                                 nullptr, 0, nullptr, 0);
            
            env->ReleaseByteArrayElements(key, key_bytes, JNI_ABORT);
        }
    }
    
    // 원본 함수가 있다면 호출
    typedef void (*original_aes_init_t)(JNIEnv*, jobject, jbyteArray);
    original_aes_init_t original = (original_aes_init_t)resolve_next_symbol("Java_com_sun_crypto_provider_AESCrypt_implInit");
    if (original) {
        original(env, obj, key);
    }
}

// Java DES 초기화 함수 후킹
extern "C" void Java_com_sun_crypto_provider_DESCrypt_implInit(JNIEnv* env, jobject obj, jbyteArray key) {
    if (hook_is_verbose()) {
        write(STDERR_FILENO, "[JAVA HOOK] DESCrypt.implInit called\n", 37);
    }
    
    if (key) {
        jsize keylen = env->GetArrayLength(key);
        jbyte* key_bytes = env->GetByteArrayElements(key, nullptr);
        
        if (key_bytes) {
            char log_msg[128];
            int n = snprintf(log_msg, sizeof(log_msg),
                           "[JAVA HOOK] DES key detected: %d bytes (%d bits)\n", 
                           keylen, keylen * 8);
            write(STDERR_FILENO, log_msg, n);
            
            // NDJSON 로그에 기록
            ndjson_log_key_event("java", "Java_DES_init", "java_enc", "DES",
                                 (const uint8_t*)key_bytes, keylen,
                                 nullptr, 0, nullptr, 0);
            
            env->ReleaseByteArrayElements(key, key_bytes, JNI_ABORT);
        }
    }
    
    // 원본 함수가 있다면 호출
    typedef void (*original_des_init_t)(JNIEnv*, jobject, jbyteArray);
    original_des_init_t original = (original_des_init_t)resolve_next_symbol("Java_com_sun_crypto_provider_DESCrypt_implInit");
    if (original) {
        original(env, obj, key);
    }
}

// 일반적인 JNI 암호화 함수 후킹을 위한 동적 심볼 해결
static void hook_java_crypto_symbols() {
    // 현재 로드된 라이브러리들을 스캔
    scan_loaded_libraries_for_crypto();
    
    // dlsym을 사용해서 Java 암호화 심볼들을 찾아서 후킹
    for (int i = 0; java_crypto_symbols[i]; i++) {
        void* sym = dlsym(RTLD_DEFAULT, java_crypto_symbols[i]);
        if (sym) {
            if (hook_is_verbose()) {
                char log_msg[256];
                int n = snprintf(log_msg, sizeof(log_msg),
                               "[JAVA NATIVE] Found crypto symbol: %s\n", 
                               java_crypto_symbols[i]);
                write(STDERR_FILENO, log_msg, n);
            }
        }
    }
}

// Java 네이티브 암호화 후킹 초기화
void init_java_native_crypto_hooks(void) {
    if (hook_is_verbose()) {
        write(STDERR_FILENO, "[JAVA NATIVE] Initializing native crypto hooks\n", 48);
    }
    
    // Java 암호화 심볼 후킹
    hook_java_crypto_symbols();
}

#endif // JAVA_SUPPORT_ENABLED
