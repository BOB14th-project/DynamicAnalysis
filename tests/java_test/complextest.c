// openssl_complex.c
// 빌드: gcc -std=c11 -O2 -m64 -o openssl_complex openssl_complex.c -lssl -lcrypto
// 또는: gcc $(pkg-config --cflags openssl) -o openssl_complex openssl_complex.c $(pkg-config --libs openssl)

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

static void fail_if(int cond, const char *msg) {
    if (cond) {
        fprintf(stderr, "ERROR: %s\n", msg);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s (%zu): ", label, len);
    for (size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

/* 1) RSA keypair 생성 및 서명 */
static EVP_PKEY *gen_rsa_key(int bits) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    fail_if(!ctx, "EVP_PKEY_CTX_new_id");
    fail_if(EVP_PKEY_keygen_init(ctx) <= 0, "EVP_PKEY_keygen_init");
    fail_if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0, "set_rsa_bits");
    EVP_PKEY *pkey = NULL;
    fail_if(EVP_PKEY_keygen(ctx, &pkey) <= 0, "EVP_PKEY_keygen");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static void rsa_sign_verify(EVP_PKEY *pkey, const unsigned char *msg, size_t msglen) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    fail_if(!mdctx, "EVP_MD_CTX_new");
    fail_if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0, "DigestSignInit");
    fail_if(EVP_DigestSignUpdate(mdctx, msg, msglen) <= 0, "DigestSignUpdate");
    size_t siglen = 0;
    fail_if(EVP_DigestSignFinal(mdctx, NULL, &siglen) <= 0, "DigestSignFinal(len)");
    unsigned char *sig = OPENSSL_malloc(siglen);
    fail_if(!sig, "OPENSSL_malloc sig");
    fail_if(EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0, "DigestSignFinal");
    print_hex("RSA-Signature", sig, siglen);

    // 검증
    EVP_MD_CTX *vctx = EVP_MD_CTX_new();
    fail_if(!vctx, "EVP_MD_CTX_new vctx");
    fail_if(EVP_DigestVerifyInit(vctx, NULL, EVP_sha256(), NULL, pkey) <= 0, "DigestVerifyInit");
    fail_if(EVP_DigestVerifyUpdate(vctx, msg, msglen) <= 0, "DigestVerifyUpdate");
    int ok = EVP_DigestVerifyFinal(vctx, sig, siglen);
    printf("RSA verify: %s\n", ok == 1 ? "OK" : "FAIL");
    EVP_MD_CTX_free(mdctx);
    EVP_MD_CTX_free(vctx);
    OPENSSL_free(sig);
}

/* 2) AES-256-GCM 암·복호화 */
static void aes_gcm_encrypt_decrypt(const unsigned char *key, const unsigned char *iv, const unsigned char *pt, int ptlen) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    fail_if(!ctx, "EVP_CIPHER_CTX_new");
    fail_if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0, "EncryptInit_ex");
    fail_if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) <= 0, "set ivlen");
    fail_if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) <= 0, "EncryptInit key/iv");
    unsigned char out[1024];
    int outlen=0, tmplen=0;
    fail_if(EVP_EncryptUpdate(ctx, out, &outlen, pt, ptlen) <= 0, "EncryptUpdate");
    if (EVP_EncryptFinal_ex(ctx, out+outlen, &tmplen) <= 0) {
        // GCM final may return 0 and set tag anyway
        // treat as non-fatal here
    }
    outlen += tmplen;
    unsigned char tag[16];
    fail_if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) <= 0, "get tag");
    print_hex("AES-GCM-CT", out, outlen);
    print_hex("AES-GCM-TAG", tag, 16);
    EVP_CIPHER_CTX_free(ctx);

    // 복호화
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    fail_if(!dctx, "EVP_CIPHER_CTX_new dctx");
    fail_if(EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0, "DecryptInit_ex");
    fail_if(EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) <= 0, "set ivlen d");
    fail_if(EVP_DecryptInit_ex(dctx, NULL, NULL, key, iv) <= 0, "DecryptInit key/iv");
    unsigned char dec[1024];
    int declen=0;
    fail_if(EVP_DecryptUpdate(dctx, dec, &declen, out, outlen) <= 0, "DecryptUpdate");
    fail_if(EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, tag) <= 0, "set tag d");
    int rv = EVP_DecryptFinal_ex(dctx, dec+declen, &tmplen);
    if (rv > 0) {
        declen += tmplen;
        printf("AES-GCM decrypt OK\n");
    } else {
        printf("AES-GCM decrypt FAIL\n");
    }
    EVP_CIPHER_CTX_free(dctx);
}

/* 3) HMAC-SHA256 */
static void do_hmac(const unsigned char *key, int keylen, const unsigned char *data, int datalen) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen=0;
    HMAC(EVP_sha256(), key, keylen, data, datalen, md, &mdlen);
    print_hex("HMAC-SHA256", md, mdlen);
}

/* 4) PBKDF2 */
static void do_pbkdf2(const char *pw, const unsigned char *salt, int saltlen) {
    unsigned char out[32];
    fail_if(!PKCS5_PBKDF2_HMAC(pw, strlen(pw), salt, saltlen, 10000, EVP_sha256(), sizeof(out), out), "PBKDF2");
    print_hex("PBKDF2(10000)", out, sizeof(out));
}

/* 5) ECDH (X25519 or prime256v1) - 예시: prime256v1 */
static void ecdh_demo() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    fail_if(!pctx, "EVP_PKEY_CTX_new_id ec");
    fail_if(EVP_PKEY_keygen_init(pctx) <= 0, "EC keygen init");
    fail_if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0, "set curve");
    EVP_PKEY *privA = NULL, *privB = NULL;
    fail_if(EVP_PKEY_keygen(pctx, &privA) <= 0, "keygen A");
    fail_if(EVP_PKEY_keygen(pctx, &privB) <= 0, "keygen B");
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privA, NULL);
    fail_if(!ctx, "EVP_PKEY_CTX_new derive");
    fail_if(EVP_PKEY_derive_init(ctx) <= 0, "derive init");
    fail_if(EVP_PKEY_derive_set_peer(ctx, privB) <= 0, "derive set peer");
    size_t secret_len = 0;
    fail_if(EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0, "derive len");
    unsigned char *secret = OPENSSL_malloc(secret_len);
    fail_if(!secret, "malloc secret");
    fail_if(EVP_PKEY_derive(ctx, secret, &secret_len) <= 0, "derive");
    print_hex("ECDH SharedSecret", secret, secret_len);
    OPENSSL_free(secret);
    EVP_PKEY_free(privA);
    EVP_PKEY_free(privB);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(ctx);
}

/* 6) 간단한 TLS 연결 (OpenSSL SSL_connect) */
static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int sfd = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    for (rp = res; rp; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sfd);
        sfd = -1;
    }
    freeaddrinfo(res);
    return sfd;
}

static void tls_connect_sample(const char *host, const char *port) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    fail_if(!ctx, "SSL_CTX_new");

    // 기본 인증서 검증은 꺼두지 않음. 필요 시 SSL_CTX_set_verify 설정.
    SSL *ssl = SSL_new(ctx);
    int sock = tcp_connect(host, port);
    if (sock < 0) { fprintf(stderr, "tcp connect fail\n"); SSL_free(ssl); SSL_CTX_free(ctx); return; }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("TLS connected: %s\n", SSL_get_cipher(ssl));
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            BIO *bio = BIO_new(BIO_s_mem());
            PEM_write_bio_X509(bio, cert);
            char buf[4096];
            int n = BIO_read(bio, buf, sizeof(buf)-1);
            if (n>0) {
                buf[n]=0;
                printf("Peer cert PEM (truncated):\\n%.*s\\n", n<200?n:200, buf);
            }
            BIO_free(bio);
            X509_free(cert);
        }
    }
    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    printf("==== OpenSSL complex demo start ====\n");

    // 랜덤 키/IV
    unsigned char key[32], iv[12];
    fail_if(RAND_bytes(key, sizeof(key)) != 1, "RAND_bytes key");
    fail_if(RAND_bytes(iv, sizeof(iv)) != 1, "RAND_bytes iv");
    print_hex("RAND-key", key, sizeof(key));
    print_hex("RAND-iv", iv, sizeof(iv));

    // RSA 서명/검증
    EVP_PKEY *rsa = gen_rsa_key(2048);
    const unsigned char msg[] = "sample message for signing";
    rsa_sign_verify(rsa, msg, sizeof(msg)-1);
    EVP_PKEY_free(rsa);

    // AES-GCM encrypt/decrypt
    const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    aes_gcm_encrypt_decrypt(key, iv, plaintext, sizeof(plaintext)-1);

    // HMAC
    do_hmac(key, sizeof(key), plaintext, sizeof(plaintext)-1);

    // PBKDF2
    unsigned char salt[16];
    fail_if(RAND_bytes(salt, sizeof(salt)) != 1, "RAND_bytes salt");
    print_hex("PBKDF2-salt", salt, sizeof(salt));
    do_pbkdf2("password123", salt, sizeof(salt));

    // ECDH
    ecdh_demo();

    // TLS 연결 (예: example.com:443)
    tls_connect_sample("example.com", "443");

    printf("==== done ====\n");

    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
