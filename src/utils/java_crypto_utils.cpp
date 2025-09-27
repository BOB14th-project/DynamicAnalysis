// java_crypto_utils.cpp
#include "pch.h"

#ifdef JAVA_SUPPORT_ENABLED
#include "java_crypto_utils.h"
#include "output.h"
#include "log.h"
#include <cstring>

// 원본 JNI 함수 포인터들
FindClass_t real_FindClass = nullptr;
GetMethodID_t real_GetMethodID = nullptr;
GetStaticMethodID_t real_GetStaticMethodID = nullptr;
CallStaticObjectMethod_t real_CallStaticObjectMethod = nullptr;
CallVoidMethod_t real_CallVoidMethod = nullptr;

// Java 암호화 알고리즘 이름 매핑 테이블
static const char* java_cipher_algorithms[] = {
    "AES", "DES", "DESede", "3DES", "TripleDES",
    "Blowfish", "RC4", "ChaCha20", "RSA", "ECC"
};

static const char* java_cipher_modes[] = {
    "ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM"
};

static const char* java_cipher_paddings[] = {
    "NoPadding", "PKCS1Padding", "PKCS5Padding", "OAEPPadding"
};

// transformation 문자열 파싱 (예: "AES/CBC/PKCS5Padding")
void parse_transformation(const char* transformation, char* algorithm, char* mode, char* padding) {
    if (!transformation) return;
    
    const char* slash1 = strchr(transformation, '/');
    if (slash1) {
        size_t algo_len = slash1 - transformation;
        strncpy(algorithm, transformation, algo_len);
        algorithm[algo_len] = '\0';
        
        const char* slash2 = strchr(slash1 + 1, '/');
        if (slash2) {
            size_t mode_len = slash2 - slash1 - 1;
            strncpy(mode, slash1 + 1, mode_len);
            mode[mode_len] = '\0';
            strcpy(padding, slash2 + 1);
        } else {
            strcpy(mode, slash1 + 1);
            padding[0] = '\0';
        }
    } else {
        strcpy(algorithm, transformation);
        mode[0] = '\0';
        padding[0] = '\0';
    }
}

// Java 바이트 배열에서 데이터 추출
int extract_java_byte_array(JNIEnv* env, jbyteArray byte_array, unsigned char* buffer, int max_len) {
    if (!env || !byte_array || !buffer) return 0;
    
    jsize array_len = env->GetArrayLength(byte_array);
    if (array_len <= 0 || array_len > max_len) return 0;
    
    jbyte* bytes = env->GetByteArrayElements(byte_array, nullptr);
    if (!bytes) return 0;
    
    memcpy(buffer, bytes, array_len);
    env->ReleaseByteArrayElements(byte_array, bytes, JNI_ABORT);
    
    return array_len;
}

// Java SecretKeySpec에서 키 정보 추출
void extract_secret_key_info(JNIEnv* env, jobject key_obj, unsigned char* key_buffer, int* key_len, char* algorithm) {
    if (!env || !key_obj) return;
    
    jclass key_class = env->GetObjectClass(key_obj);
    if (!key_class) return;
    
    // getEncoded() 메서드로 키 바이트 배열 가져오기
    jmethodID get_encoded_method = env->GetMethodID(key_class, "getEncoded", "()[B");
    if (get_encoded_method) {
        jbyteArray key_bytes = (jbyteArray)env->CallObjectMethod(key_obj, get_encoded_method);
        if (key_bytes) {
            *key_len = extract_java_byte_array(env, key_bytes, key_buffer, 256);
        }
    }
    
    // getAlgorithm() 메서드로 알고리즘 이름 가져오기
    jmethodID get_algorithm_method = env->GetMethodID(key_class, "getAlgorithm", "()Ljava/lang/String;");
    if (get_algorithm_method) {
        jstring algo_str = (jstring)env->CallObjectMethod(key_obj, get_algorithm_method);
        if (algo_str) {
            const char* algo_chars = env->GetStringUTFChars(algo_str, nullptr);
            if (algo_chars) {
                strncpy(algorithm, algo_chars, 63);
                algorithm[63] = '\0';
                env->ReleaseStringUTFChars(algo_str, algo_chars);
            }
        }
    }
    
    env->DeleteLocalRef(key_class);
}

// Java IvParameterSpec에서 IV 정보 추출
int extract_iv_info(JNIEnv* env, jobject iv_obj, unsigned char* iv_buffer) {
    if (!env || !iv_obj) return 0;
    
    jclass iv_class = env->GetObjectClass(iv_obj);
    if (!iv_class) return 0;
    
    // getIV() 메서드로 IV 바이트 배열 가져오기
    jmethodID get_iv_method = env->GetMethodID(iv_class, "getIV", "()[B");
    int iv_len = 0;
    if (get_iv_method) {
        jbyteArray iv_bytes = (jbyteArray)env->CallObjectMethod(iv_obj, get_iv_method);
        if (iv_bytes) {
            iv_len = extract_java_byte_array(env, iv_bytes, iv_buffer, 32);
        }
    }
    
    env->DeleteLocalRef(iv_class);
    return iv_len;
}

// Cipher 객체에서 정보 추출
void extract_java_cipher_info(JNIEnv* env, jobject cipher_obj, const char* transformation) {
    if (!env || !cipher_obj) return;
    
    char algorithm[64] = {0};
    char mode[32] = {0};
    char padding[32] = {0};
    
    if (transformation) {
        parse_transformation(transformation, algorithm, mode, padding);
    }
    
    // 로그 출력
    char log_msg[256];
    int n = snprintf(log_msg, sizeof(log_msg), 
                     "[JAVA HOOK] Cipher created: %s (mode: %s, padding: %s)\n",
                     algorithm[0] ? algorithm : "unknown",
                     mode[0] ? mode : "unknown", 
                     padding[0] ? padding : "unknown");
    write(STDERR_FILENO, log_msg, n);
}

// Java 키 정보 추출
void extract_java_key_info(JNIEnv* env, jobject key_obj, const char* algorithm) {
    if (!env || !key_obj) return;
    
    unsigned char key_buffer[256] = {0};
    int key_len = 0;
    char key_algorithm[64] = {0};
    
    extract_secret_key_info(env, key_obj, key_buffer, &key_len, key_algorithm);
    
    if (key_len > 0) {
        char log_msg[128];
        int n = snprintf(log_msg, sizeof(log_msg),
                         "[JAVA HOOK] Key: algorithm=%s, length=%d bytes (%d bits)\n",
                         key_algorithm[0] ? key_algorithm : (algorithm ? algorithm : "unknown"),
                         key_len, key_len * 8);
        write(STDERR_FILENO, log_msg, n);
        
        // 키를 16진수로 출력
        write(STDERR_FILENO, "[JAVA HOOK] Key data: ", 22);
        for (int i = 0; i < key_len; i++) {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", key_buffer[i]);
            write(STDERR_FILENO, hex, 2);
        }
        write(STDERR_FILENO, "\n", 1);
        
        // NDJSON 로그에 기록
        log_java_crypto_operation("java_key_init", 
                                key_algorithm[0] ? key_algorithm : algorithm,
                                key_buffer, key_len, nullptr, 0);
    }
}

// Java 암호화 작업 로깅
void log_java_crypto_operation(const char* operation, const char* algorithm, 
                              const unsigned char* key_data, int key_len,
                              const unsigned char* iv_data, int iv_len) {
    // NDJSON 형식으로 로깅
    const char* op = operation ? operation : "java_op";
    ndjson_log_key_event("java", op, "java", algorithm,
                         key_data, key_len,
                         iv_data, iv_len,
                         nullptr, 0);
}

// 암호화 관련 클래스인지 확인
int is_java_crypto_class(const char* class_name) {
    if (!class_name) return 0;
    
    return (strstr(class_name, "javax/crypto/") != nullptr ||
            strstr(class_name, "java/security/") != nullptr ||
            strstr(class_name, "Cipher") != nullptr ||
            strstr(class_name, "SecretKey") != nullptr ||
            strstr(class_name, "KeySpec") != nullptr);
}

#endif // JAVA_SUPPORT_ENABLED
