// get_key.h
#pragma once
#include <openssl/evp.h>

// get safe key len
int get_effective_keylen(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type);
// key dump
void dump_hex_stderr(const unsigned char* p, int n);
// print log key and length
void log_key_and_len(const char* api,
                     const char* direction,
                     EVP_CIPHER_CTX* ctx,
                     const EVP_CIPHER* type,
                     const unsigned char* key);


#if OPENSSL_VERSION_NUMBER >= 0x300000
#include <openssl/params.h>
#include <openssl/core_names.h>
void log_key_iv_from_params(const OSSL_PARAM* params);
#endif