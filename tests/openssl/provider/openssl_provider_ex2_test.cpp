#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

static void dump_hex(const char* title, const unsigned char* p, size_t n) {
    std::cout << title << " (" << n << "): ";
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < n; ++i) std::cout << std::setw(2) << (int)p[i];
    std::cout << std::dec << "\n";
}

int main() {
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    std::cerr << "This test requires OpenSSL 3.x\n";
    return 1;
#endif
    const size_t KEYLEN = 32;       // AES-256
    const size_t IVLEN  = 12;       // GCM 권장
    const size_t TAGLEN = 16;       // GCM 태그

    std::vector<unsigned char> key(KEYLEN), iv(IVLEN), tag(TAGLEN);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    std::string msg = "hello ex2 + params (AES-256-GCM)";
    std::vector<unsigned char> pt(msg.begin(), msg.end());
    std::vector<unsigned char> ct(pt.size());

    // -------------------- Encrypt (ex2 + params: IVLEN) --------------------
    EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* ciph = EVP_aes_256_gcm();  // provider 기본

    OSSL_PARAM eparams[] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                    const_cast<size_t*>(&IVLEN)),
        OSSL_PARAM_construct_end()
    };

    if (!EVP_EncryptInit_ex2(ectx, ciph, key.data(), iv.data(), eparams)) {
        std::cerr << "EncryptInit_ex2 failed\n"; return 1;
    }

    int outl = 0, tot = 0;
    if (!EVP_EncryptUpdate(ectx, ct.data(), &outl, pt.data(), (int)pt.size())) {
        std::cerr << "EncryptUpdate failed\n"; return 1;
    }
    tot += outl;
    if (!EVP_EncryptFinal_ex(ectx, ct.data()+tot, &outl)) {
        std::cerr << "EncryptFinal_ex failed\n"; return 1;
    }
    tot += outl;
    ct.resize(tot);

    // 태그 얻기 (encrypt 시엔 ctrl로 GET_TAG)
    if (!EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data())) {
        std::cerr << "GET_TAG failed\n"; return 1;
    }
    EVP_CIPHER_CTX_free(ectx);

    dump_hex("key", key.data(), key.size());
    dump_hex("iv", iv.data(), iv.size());
    dump_hex("ct", ct.data(), ct.size());
    dump_hex("tag", tag.data(), tag.size());

    // -------------------- Decrypt (ex2 + params: IVLEN, TAG) --------------------
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();

    // 복호에서는 태그를 params로 전달 가능
    OSSL_PARAM dparams[] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
                                    const_cast<size_t*>(&IVLEN)),
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                          tag.data(), tag.size()),
        OSSL_PARAM_construct_end()
    };

    if (!EVP_DecryptInit_ex2(dctx, ciph, key.data(), iv.data(), dparams)) {
        std::cerr << "DecryptInit_ex2 failed\n"; return 1;
    }

    std::vector<unsigned char> rec(pt.size());
    tot = 0;
    if (!EVP_DecryptUpdate(dctx, rec.data(), &outl, ct.data(), (int)ct.size())) {
        std::cerr << "DecryptUpdate failed\n"; return 1;
    }
    tot += outl;

    // 태그는 이미 params로 세팅했으므로 바로 Final
    if (!EVP_DecryptFinal_ex(dctx, rec.data()+tot, &outl)) {
        std::cerr << "DecryptFinal_ex failed (auth tag mismatch?)\n"; return 1;
    }
    tot += outl;
    rec.resize(tot);
    EVP_CIPHER_CTX_free(dctx);

    std::string recovered(rec.begin(), rec.end());
    std::cout << "recovered: " << recovered << "\n";
    std::cout << ((recovered == msg) ? "OK\n" : "MISMATCH\n");
    return 0;
}
