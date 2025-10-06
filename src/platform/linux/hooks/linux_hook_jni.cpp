// hook_jni.cpp
#include "common/pch.h"

#ifdef JAVA_SUPPORT_ENABLED
#include "platform/linux/hook_jni.h"
#include "platform/linux/java_crypto_utils.h"
#include "platform/linux/resolver.h"
#include "common/hook_common.h"
#include <stdarg.h>
#include <errno.h>

namespace {

void write_stderr_buffer(const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = write(STDERR_FILENO, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        data += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
}

} // namespace

// 원본 JNI 함수 포인터 타입 정의
typedef jclass (*jni_findclass_t)(JNIEnv*, const char*);
typedef jmethodID (*jni_getmethodid_t)(JNIEnv*, jclass, const char*, const char*);
typedef jmethodID (*jni_getstaticmethodid_t)(JNIEnv*, jclass, const char*, const char*);
typedef jobject (*jni_callstaticobjectmethod_t)(JNIEnv*, jclass, jmethodID, ...);
typedef jobject (*jni_callstaticobjectmethodv_t)(JNIEnv*, jclass, jmethodID, va_list);
typedef void (*jni_callvoidmethod_t)(JNIEnv*, jobject, jmethodID, ...);
typedef void (*jni_callvoidmethodv_t)(JNIEnv*, jobject, jmethodID, va_list);

// 원본 JNI 함수들
static jni_findclass_t real_jni_FindClass = nullptr;
static jni_getmethodid_t real_jni_GetMethodID = nullptr;
static jni_getstaticmethodid_t real_jni_GetStaticMethodID = nullptr;
static jni_callstaticobjectmethod_t real_jni_CallStaticObjectMethod = nullptr;
static jni_callstaticobjectmethodv_t real_jni_CallStaticObjectMethodV = nullptr;
static jni_callvoidmethod_t real_jni_CallVoidMethod = nullptr;
static jni_callvoidmethodv_t real_jni_CallVoidMethodV = nullptr;

// 추적할 클래스와 메서드 정보 저장
static struct {
    jclass cipher_class;
    jmethodID cipher_getinstance_method;
    jmethodID cipher_init_method;
    jmethodID cipher_init_with_params_method;
    jclass secretkeyspec_class;
    jclass ivparameterspec_class;
} java_crypto_cache{};

// 암호화 관련 클래스인지 확인 (java_crypto_utils.cpp에서 구현된 함수 사용)
int is_crypto_class(const char* class_name) {
    if (!class_name) return 0;
    
    return (strstr(class_name, "javax/crypto/") != nullptr ||
            strstr(class_name, "java/security/") != nullptr ||
            strstr(class_name, "Cipher") != nullptr ||
            strstr(class_name, "SecretKey") != nullptr ||
            strstr(class_name, "KeySpec") != nullptr);
}

// Cipher 관련 메서드인지 확인
int is_cipher_method(const char* method_name, const char* signature) {
    (void)signature;
    if (!method_name) return 0;
    
    return (strcmp(method_name, "getInstance") == 0 ||
            strcmp(method_name, "init") == 0 ||
            strcmp(method_name, "doFinal") == 0 ||
            strcmp(method_name, "update") == 0);
}

// FindClass 후킹 - Java 클래스 로딩 감시
JNIEXPORT jclass JNICALL FindClass(JNIEnv* env, const char* name) {
    if (!real_jni_FindClass) {
        real_jni_FindClass = (jni_findclass_t)resolve_next_symbol("FindClass");
        if (!real_jni_FindClass) return nullptr;
    }
    
    // 암호화 관련 클래스 탐지
    if (is_crypto_class(name)) {
        if (hook_is_verbose()) {
            char log_msg[256];
            int n = snprintf(log_msg, sizeof(log_msg), 
                           "[JAVA HOOK] Loading crypto class: %s\n", name);
            if (n > 0) {
                write_stderr_buffer(log_msg, static_cast<size_t>(n));
            }
        }
        
        jclass result = real_jni_FindClass(env, name);
        
        // 중요한 클래스들 캐싱
        if (strcmp(name, JAVAX_CRYPTO_CIPHER_CLASS) == 0) {
            java_crypto_cache.cipher_class = (jclass)env->NewGlobalRef(result);
        } else if (strcmp(name, JAVAX_CRYPTO_SPEC_SECRETKEYSPEC_CLASS) == 0) {
            java_crypto_cache.secretkeyspec_class = (jclass)env->NewGlobalRef(result);
        } else if (strcmp(name, JAVAX_CRYPTO_SPEC_IVPARAMETERSPEC_CLASS) == 0) {
            java_crypto_cache.ivparameterspec_class = (jclass)env->NewGlobalRef(result);
        }
        
        return result;
    }
    
    return real_jni_FindClass(env, name);
}

// GetMethodID 후킹 - Java 메서드 ID 획득 감시
JNIEXPORT jmethodID JNICALL GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    if (!real_jni_GetMethodID) {
        real_jni_GetMethodID = (jni_getmethodid_t)resolve_next_symbol("GetMethodID");
        if (!real_jni_GetMethodID) return nullptr;
    }
    
    // Cipher 메서드 탐지
    if (is_cipher_method(name, sig)) {
        if (hook_is_verbose()) {
            char log_msg[256];
            int n = snprintf(log_msg, sizeof(log_msg),
                           "[JAVA HOOK] Getting cipher method: %s%s\n", name, sig);
            if (n > 0) {
                write_stderr_buffer(log_msg, static_cast<size_t>(n));
            }
        }
        
        jmethodID result = real_jni_GetMethodID(env, clazz, name, sig);
        
        // 중요한 메서드들 캐싱
        if (strcmp(name, "init") == 0) {
            if (strstr(sig, "Ljava/security/Key;)V")) {
                java_crypto_cache.cipher_init_method = result;
            } else if (strstr(sig, "Ljava/security/spec/AlgorithmParameterSpec;")) {
                java_crypto_cache.cipher_init_with_params_method = result;
            }
        }
        
        return result;
    }
    
    return real_jni_GetMethodID(env, clazz, name, sig);
}

// GetStaticMethodID 후킹
JNIEXPORT jmethodID JNICALL GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig) {
    if (!real_jni_GetStaticMethodID) {
        real_jni_GetStaticMethodID = (jni_getstaticmethodid_t)resolve_next_symbol("GetStaticMethodID");
        if (!real_jni_GetStaticMethodID) return nullptr;
    }
    
    // Cipher.getInstance() 탐지
    if (strcmp(name, "getInstance") == 0 && strstr(sig, "Ljavax/crypto/Cipher;")) {
        if (hook_is_verbose()) {
            char log_msg[128];
            int n = snprintf(log_msg, sizeof(log_msg),
                           "[JAVA HOOK] Getting Cipher.getInstance method\n");
            if (n > 0) {
                write_stderr_buffer(log_msg, static_cast<size_t>(n));
            }
        }
        
        jmethodID result = real_jni_GetStaticMethodID(env, clazz, name, sig);
        java_crypto_cache.cipher_getinstance_method = result;
        return result;
    }
    
    return real_jni_GetStaticMethodID(env, clazz, name, sig);
}

// CallStaticObjectMethod 후킹 - Cipher.getInstance() 호출 감시
JNIEXPORT jobject JNICALL CallStaticObjectMethod(JNIEnv* env, jclass clazz, jmethodID methodID, ...) {
    if (!real_jni_CallStaticObjectMethod) {
        real_jni_CallStaticObjectMethod = (jni_callstaticobjectmethod_t)resolve_next_symbol("CallStaticObjectMethod");
        if (!real_jni_CallStaticObjectMethod) return nullptr;
    }
    
    va_list args;
    va_start(args, methodID);
    
    // Cipher.getInstance() 호출 탐지
    if (methodID == java_crypto_cache.cipher_getinstance_method) {
        jstring transformation = va_arg(args, jstring);
        const char* trans_str = nullptr;
        
        if (transformation) {
            trans_str = env->GetStringUTFChars(transformation, nullptr);
            if (trans_str) {
                if (hook_is_verbose()) {
                    char log_msg[256];
                    int n = snprintf(log_msg, sizeof(log_msg),
                                   "[JAVA HOOK] Cipher.getInstance(\"%s\")\n", trans_str);
                    if (n > 0) {
                        write_stderr_buffer(log_msg, static_cast<size_t>(n));
                    }
                }
            }
        }
        
        va_end(args);
        va_start(args, methodID);
        jobject result = real_jni_CallStaticObjectMethodV(env, clazz, methodID, args);
        
        // Cipher 객체 정보 추출
        if (result && trans_str) {
            extract_java_cipher_info(env, result, trans_str);
        }
        
        if (trans_str) {
            env->ReleaseStringUTFChars(transformation, trans_str);
        }
        
        va_end(args);
        return result;
    }
    
    jobject result = real_jni_CallStaticObjectMethodV(env, clazz, methodID, args);
    va_end(args);
    return result;
}

// CallStaticObjectMethodV 후킹 
JNIEXPORT jobject JNICALL CallStaticObjectMethodV(JNIEnv* env, jclass clazz, jmethodID methodID, va_list args) {
    if (!real_jni_CallStaticObjectMethodV) {
        real_jni_CallStaticObjectMethodV = (jni_callstaticobjectmethodv_t)resolve_next_symbol("CallStaticObjectMethodV");
        if (!real_jni_CallStaticObjectMethodV) return nullptr;
    }
    
    return real_jni_CallStaticObjectMethodV(env, clazz, methodID, args);
}

// CallVoidMethod 후킹 - Cipher.init() 호출 감시
JNIEXPORT void JNICALL CallVoidMethod(JNIEnv* env, jobject obj, jmethodID methodID, ...) {
    if (!real_jni_CallVoidMethod) {
        real_jni_CallVoidMethod = (jni_callvoidmethod_t)resolve_next_symbol("CallVoidMethod");
        if (!real_jni_CallVoidMethod) return;
    }
    
    va_list args;
    va_start(args, methodID);
    
    // Cipher.init() 호출 탐지
    if (methodID == java_crypto_cache.cipher_init_method || 
        methodID == java_crypto_cache.cipher_init_with_params_method) {
        
        jint mode = va_arg(args, jint);
        jobject key = va_arg(args, jobject);
        
        const char* mode_str = (mode == 1) ? "encrypt" : 
                              (mode == 2) ? "decrypt" : 
                              (mode == 3) ? "wrap" : 
                              (mode == 4) ? "unwrap" : "unknown";
        
        if (hook_is_verbose()) {
            char log_msg[128];
            int n = snprintf(log_msg, sizeof(log_msg),
                           "[JAVA HOOK] Cipher.init(mode=%s)\n", mode_str);
            if (n > 0) {
                write_stderr_buffer(log_msg, static_cast<size_t>(n));
            }
        }
        
        // 키 정보 추출
        if (key) {
            extract_java_key_info(env, key, nullptr);
        }
        
        // IV 파라미터가 있는 경우 추출
        if (methodID == java_crypto_cache.cipher_init_with_params_method) {
            jobject params = va_arg(args, jobject);
            if (params && hook_is_verbose()) {
                // IV 정보 추출은 향후 구현 예정
                char log_msg[64];
                int n = snprintf(log_msg, sizeof(log_msg),
                               "[JAVA HOOK] IV parameter detected\n");
                if (n > 0) {
                    write_stderr_buffer(log_msg, static_cast<size_t>(n));
                }
            }
        }
    }
    
    va_end(args);
    va_start(args, methodID);
    real_jni_CallVoidMethodV(env, obj, methodID, args);
    va_end(args);
}

// CallVoidMethodV 후킹
JNIEXPORT void JNICALL CallVoidMethodV(JNIEnv* env, jobject obj, jmethodID methodID, va_list args) {
    if (!real_jni_CallVoidMethodV) {
        real_jni_CallVoidMethodV = (jni_callvoidmethodv_t)resolve_next_symbol("CallVoidMethodV");
        if (!real_jni_CallVoidMethodV) return;
    }
    
    real_jni_CallVoidMethodV(env, obj, methodID, args);
}

// Java 암호화 후킹 초기화
void hook_java_crypto_init(void) {
    memset(&java_crypto_cache, 0, sizeof(java_crypto_cache));
    
    if (hook_is_verbose()) {
        static const char kInitMsg[] = "[JAVA HOOK] JNI crypto hooks initialized\n";
        write_stderr_buffer(kInitMsg, sizeof(kInitMsg) - 1);
    }
}

#endif // JAVA_SUPPORT_ENABLED
