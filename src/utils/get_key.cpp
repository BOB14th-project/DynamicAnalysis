// get_key.cpp
#include "pch.h"
#include "get_key.h"

// OpenSSL/LibreSSL 버전별 안전한 키 길이 얻기
int get_effective_keylen(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type) {
#if defined(LIBRESSL_VERSION_NUMBER)
    // LibreSSL은 1.1.x 계열과 유사 API
    int l = EVP_CIPHER_CTX_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_cipher(ctx);
    return c ? EVP_CIPHER_key_length(c) : 0;
#elif OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x
    int l = EVP_CIPHER_CTX_get_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_get0_cipher(ctx);
    return c ? EVP_CIPHER_get_key_length(c) : 0;
#else
    // OpenSSL 1.1.0/1.1.1
    int l = EVP_CIPHER_CTX_key_length(ctx);
    if (l > 0) return l;
    const EVP_CIPHER* c = type ? type : EVP_CIPHER_CTX_cipher(ctx);
    return c ? EVP_CIPHER_key_length(c) : 0;
#endif
}

// key dump
void dump_hex_stderr(const unsigned char* p, int n) {
    if (!p || n <= 0) return;
    char buf[3]; // 2 hex + NUL
    for (int i = 0; i < n; ++i) {
        int m = snprintf(buf, sizeof(buf), "%02x", p[i]);
        (void)!write(STDERR_FILENO, buf, (size_t)m);
    }
    (void)!write(STDERR_FILENO, "\n", 1);
}