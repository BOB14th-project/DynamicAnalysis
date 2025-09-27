// hook_jni.h
#pragma once

#ifdef JAVA_SUPPORT_ENABLED
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// JNI 함수 후킹을 위한 선언들
JNIEXPORT jclass JNICALL FindClass(JNIEnv* env, const char* name);
JNIEXPORT jmethodID JNICALL GetMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig);
JNIEXPORT jmethodID JNICALL GetStaticMethodID(JNIEnv* env, jclass clazz, const char* name, const char* sig);
JNIEXPORT jobject JNICALL CallStaticObjectMethodV(JNIEnv* env, jclass clazz, jmethodID methodID, va_list args);
JNIEXPORT jobject JNICALL CallStaticObjectMethod(JNIEnv* env, jclass clazz, jmethodID methodID, ...);
JNIEXPORT void JNICALL CallVoidMethodV(JNIEnv* env, jobject obj, jmethodID methodID, va_list args);
JNIEXPORT void JNICALL CallVoidMethod(JNIEnv* env, jobject obj, jmethodID methodID, ...);

// Java 암호화 클래스 탐지 함수들
int is_crypto_class(const char* class_name);
int is_cipher_method(const char* method_name, const char* signature);
void hook_java_crypto_init(void);

#ifdef __cplusplus
}
#endif

#endif // JAVA_SUPPORT_ENABLED
