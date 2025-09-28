#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <string.h>
#include <vector>

static int generate_ecc_key(EVP_PKEY** out_key) {
    EVP_PKEY_CTX* param_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!param_ctx) {
        return 0;
    }

    int ok = EVP_PKEY_paramgen_init(param_ctx) > 0 &&
             EVP_PKEY_CTX_set_ec_paramgen_curve_nid(param_ctx, NID_secp256k1) > 0;

    EVP_PKEY* params = nullptr;
    if (ok) {
        ok = EVP_PKEY_paramgen(param_ctx, &params) > 0;
    }
    EVP_PKEY_CTX_free(param_ctx);
    if (!ok || !params) {
        EVP_PKEY_free(params);
        return 0;
    }

    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_free(params);
    if (!key_ctx) {
        return 0;
    }

    ok = EVP_PKEY_keygen_init(key_ctx) > 0;
    if (ok) {
        ok = EVP_PKEY_keygen(key_ctx, out_key) > 0;
    }
    EVP_PKEY_CTX_free(key_ctx);
    return ok && *out_key;
}

static int sign_digest(EVP_PKEY* key,
                       const unsigned char* digest,
                       size_t digest_len,
                       std::vector<unsigned char>& signature) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return 0;
    }

    int ok = EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, key) > 0;
    if (ok) {
        ok = EVP_DigestSignUpdate(md_ctx, digest, digest_len) > 0;
    }

    size_t sig_len = 0;
    if (ok) {
        ok = EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) > 0;
    }

    if (ok) {
        signature.resize(sig_len);
        ok = EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) > 0;
        if (ok) {
            signature.resize(sig_len);
        }
    }

    EVP_MD_CTX_free(md_ctx);
    return ok;
}

static int verify_digest(EVP_PKEY* key,
                         const unsigned char* digest,
                         size_t digest_len,
                         const std::vector<unsigned char>& signature) {
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        return 0;
    }

    int ok = EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, key) > 0;
    if (ok) {
        ok = EVP_DigestVerifyUpdate(md_ctx, digest, digest_len) > 0;
    }
    if (ok) {
        ok = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size()) > 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return ok;
}

int main() {
    EVP_PKEY* pkey = nullptr;
    if (!generate_ecc_key(&pkey)) {
        printf("Error generating ECC key\n");
        return 1;
    }

    // 공개키 출력
    PEM_write_PUBKEY(stdout, pkey);

    const char* message = "Hello, ECC!";

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)message, strlen(message), digest);

    printf("\nMessage Digest (SHA-256):\n");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n\n");

    std::vector<unsigned char> signature;
    if (!sign_digest(pkey, digest, sizeof(digest), signature)) {
        printf("Error signing message digest\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    if (verify_digest(pkey, digest, sizeof(digest), signature)) {
        printf("Signature Verified Successfully\n");
    } else {
        printf("Signature Verification Failed\n");
        EVP_PKEY_free(pkey);
        return 1;
    }

    EVP_PKEY_free(pkey);
    printf("Program finished.\n");
    return 0;
}
