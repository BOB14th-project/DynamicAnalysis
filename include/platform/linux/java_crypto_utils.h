// java_crypto_utils.h
#pragma once

#ifdef JAVA_SUPPORT_ENABLED
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Java 암호화 관련 클래스/메서드 시그니처들
#define JAVAX_CRYPTO_CIPHER_CLASS "javax/crypto/Cipher"
#define JAVAX_CRYPTO_SPEC_SECRETKEYSPEC_CLASS "javax/crypto/spec/SecretKeySpec"
#define JAVAX_CRYPTO_SPEC_IVPARAMETERSPEC_CLASS "javax/crypto/spec/IvParameterSpec"
#define JAVA_SECURITY_SECURERANDOM_CLASS "java/security/SecureRandom"

// Cipher 메서드들
#define CIPHER_GETINSTANCE_METHOD "getInstance"
#define CIPHER_GETINSTANCE_SIGNATURE "(Ljava/lang/String;)Ljavax/crypto/Cipher;"
#define CIPHER_INIT_METHOD "init"
#define CIPHER_INIT_SIGNATURE "(ILjava/security/Key;)V"
#define CIPHER_INIT_WITH_PARAMS_SIGNATURE "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V"

// Java 암호화 정보 추출 함수들
void extract_java_cipher_info(JNIEnv* env, jobject cipher_obj, const char* transformation);
void extract_java_key_info(JNIEnv* env, jobject key_obj, const char* algorithm);
void log_java_crypto_operation(const char* operation, const char* algorithm, 
                              const unsigned char* key_data, int key_len,
                              const unsigned char* iv_data, int iv_len);

// JNI 함수 타입 정의들
typedef jclass (*FindClass_t)(JNIEnv*, const char*);
typedef jmethodID (*GetMethodID_t)(JNIEnv*, jclass, const char*, const char*);
typedef jmethodID (*GetStaticMethodID_t)(JNIEnv*, jclass, const char*, const char*);
typedef jobject (*CallStaticObjectMethod_t)(JNIEnv*, jclass, jmethodID, ...);
typedef void (*CallVoidMethod_t)(JNIEnv*, jobject, jmethodID, ...);
typedef jbyteArray (*GetByteArrayElements_t)(JNIEnv*, jbyteArray, jboolean*);
typedef void (*ReleaseByteArrayElements_t)(JNIEnv*, jbyteArray, jbyte*, jint);
typedef jsize (*GetArrayLength_t)(JNIEnv*, jarray);

// 원본 JNI 함수 포인터들
extern FindClass_t real_FindClass;
extern GetMethodID_t real_GetMethodID;
extern GetStaticMethodID_t real_GetStaticMethodID;
extern CallStaticObjectMethod_t real_CallStaticObjectMethod;
extern CallVoidMethod_t real_CallVoidMethod;

#ifdef __cplusplus
}
#endif

#endif // JAVA_SUPPORT_ENABLED