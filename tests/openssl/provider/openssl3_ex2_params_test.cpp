// tests/openssl_test/openssl3_ex2_params_test.cpp
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static void die(const char* m){ std::fprintf(stderr,"%s\n",m); std::abort(); }

int main() {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    std::fprintf(stderr, "This test requires OpenSSL >= 3.0\n");
    return 0;
#endif
    OSSL_PROVIDER* def = OSSL_PROVIDER_load(nullptr, "default");
    if(!def) die("provider load");

    unsigned char key[32], iv[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv,  sizeof(iv));

    EVP_CIPHER* c = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
    if(!c) die("fetch cipher");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx) die("ctx");

    size_t ivlen = sizeof(iv);
    size_t taglen = 16;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen),
        OSSL_PARAM_construct_end()
    };

    // ★ ex2 정식 시그니처: (..., key, iv, params)
    if(EVP_EncryptInit_ex2(ctx, c, key, iv, params) != 1) die("ex2");

    const unsigned char pt[] = "hello provider ex2";
    unsigned char ct[128], tag[16];
    int len=0, out=0;

    if(EVP_EncryptUpdate(ctx, ct, &len, pt, (int)strlen((const char*)pt)) != 1) die("upd");
    out = len;
    if(EVP_EncryptFinal_ex(ctx, ct+out, &len) != 1) die("fin");
    out += len;

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) die("get tag");

    std::printf("ok ex2: ct=%dB\n", out);

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(c);
    if (def) OSSL_PROVIDER_unload(def);
    return 0;
}
