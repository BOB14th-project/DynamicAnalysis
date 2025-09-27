// JavaNativeSSL.c - Java에서 호출할 OpenSSL JNI 라이브러리
#include <jni.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string.h>

// Java에서 호출할 네이티브 함수
JNIEXPORT jbyteArray JNICALL Java_JavaNativeSSL_nativeAESEncrypt
  (JNIEnv *env, jobject obj, jbyteArray key, jbyteArray data) {
    
    jsize keyLen = (*env)->GetArrayLength(env, key);
    jsize dataLen = (*env)->GetArrayLength(env, data);
    
    jbyte *keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
    
    // OpenSSL EVP 사용 - 이것이 우리 후킹에 걸릴 것임!
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    // AES-256-CBC로 초기화 - 여기서 후킹됨!
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)keyBytes, NULL);
    
    unsigned char *outbuf = malloc(dataLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int outlen, tmplen;
    
    EVP_EncryptUpdate(ctx, outbuf, &outlen, (unsigned char*)dataBytes, dataLen);
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen);
    outlen += tmplen;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Java 바이트 배열로 결과 반환
    jbyteArray result = (*env)->NewByteArray(env, outlen);
    (*env)->SetByteArrayRegion(env, result, 0, outlen, (jbyte*)outbuf);
    
    free(outbuf);
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
    
    return result;
}