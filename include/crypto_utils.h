// get_key.h
#pragma once
#include <openssl/evp.h>

// get safe key len
int get_effective_keylen(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type);

// key dump
void dump_hex_stderr(const unsigned char* p, int n);

// print log key and length
void log_key_and_len(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, const unsigned char* key);