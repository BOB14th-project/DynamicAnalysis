// get_key.h
#pragma once
#include <openssl/evp.h>

// get safe key len
int get_effective_keylen(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type);

// key dump
void dump_hex_stderr(const unsigned char* p, int n);