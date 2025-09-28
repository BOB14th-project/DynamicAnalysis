#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif

static void dump_hex(const char* title, const unsigned char* p, size_t n) {
    std::cout << title << " (" << n << "): ";
    std::cout << std::hex << std::setfill('0');
    for (size_t i=0; i<n; ++i) std::cout << std::setw(2) << (int)p[i];
    std::cout << std::dec << "\n";
}

int main() {
    const size_t KEYLEN = 32;  // AES-256
    const size_t IVLEN  = 12;  // GCM 권장
    const size_t TAGLEN = 16;  // GCM 태그

    std::vector<unsigned char> key(KEYLEN), iv(IVLEN), tag(TAGLEN);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    std::string msg = "symmetric AES-256-GCM test";
    std::vector<unsigned char> pt(msg.begin(), msg.end());
    std::vector<unsigned char> ct(pt.size());
    std::vector<unsigned char> rec(pt.size());

    const EVP_CIPHER* C = EVP_aes_256_gcm();
    int outl=0, tot=0;

    // ---------- Encrypt ----------
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM eparams[] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, (size_t*)&IVLEN),
        OSSL_PARAM_construct_end()
    };
    if (!EVP_EncryptInit_ex2(ectx, C, key.data(), iv.data(), eparams)) {
        std::cerr << "EncryptInit_ex2 failed\n"; return 1;
    }
#else
    if (!EVP_EncryptInit_ex(ectx, C, nullptr, key.data(), iv.data())) {
        std::cerr << "EncryptInit_ex failed\n"; return 1;
    }
#endif
    if (!EVP_EncryptUpdate(ectx, ct.data(), &outl, pt.data(), (int)pt.size())) {
        std::cerr << "EncryptUpdate failed\n"; return 1;
    }
    tot = outl;
    if (!EVP_EncryptFinal_ex(ectx, ct.data()+tot, &outl)) {
        std::cerr << "EncryptFinal_ex failed\n"; return 1;
    }
    tot += outl;
    ct.resize(tot);
    if (!EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data())) {
        std::cerr << "GET_TAG failed\n"; return 1;
    }
    EVP_CIPHER_CTX_free(ectx);

    dump_hex("key", key.data(), key.size());
    dump_hex("iv", iv.data(), iv.size());
    dump_hex("ct", ct.data(), ct.size());
    dump_hex("tag", tag.data(), tag.size());

    // ---------- Decrypt ----------
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM dparams[] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, (size_t*)&IVLEN),
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag.data(), tag.size()),
        OSSL_PARAM_construct_end()
    };
    if (!EVP_DecryptInit_ex2(dctx, C, key.data(), iv.data(), dparams)) {
        std::cerr << "DecryptInit_ex2 failed\n"; return 1;
    }
#else
    if (!EVP_DecryptInit_ex(dctx, C, nullptr, key.data(), iv.data())) {
        std::cerr << "DecryptInit_ex failed\n"; return 1;
    }
    if (!EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), tag.data())) {
        std::cerr << "SET_TAG failed\n"; return 1;
    }
#endif
    if (!EVP_DecryptUpdate(dctx, rec.data(), &outl, ct.data(), (int)ct.size())) {
        std::cerr << "DecryptUpdate failed\n"; return 1;
    }
    tot = outl;
    if (!EVP_DecryptFinal_ex(dctx, rec.data()+tot, &outl)) {
        std::cerr << "DecryptFinal_ex failed\n"; return 1;
    }
    tot += outl;
    rec.resize(tot);
    EVP_CIPHER_CTX_free(dctx);

    std::string recovered(rec.begin(), rec.end());
    std::cout << "recovered: " << recovered << "\n";
    std::cout << ((recovered == msg) ? "OK\n" : "MISMATCH\n");

    return 0;
}
