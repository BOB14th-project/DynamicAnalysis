// nss_aes_cbc_demo.c
// AES-256-CBC encrypt/decrypt using NSS PK11 APIs.

#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/secerr.h>
#include <stdio.h>
#include <string.h>

static void bail(const char* msg) {
    fprintf(stderr, "%s (err=%d)\n", msg, PORT_GetError());
}

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        bail("NSS init failed");
        return 1;
    }

    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        bail("No internal slot");
        NSS_Shutdown();
        return 1;
    }

    unsigned char key_bytes[32];
    for (size_t i = 0; i < sizeof(key_bytes); ++i) key_bytes[i] = (unsigned char)i;
    SECItem key_item = { siBuffer, key_bytes, sizeof(key_bytes) };

    PK11SymKey* key = PK11_ImportSymKey(slot, CKM_AES_CBC_PAD, PK11_OriginUnwrap, CKA_ENCRYPT, &key_item, NULL);
    if (!key) {
        bail("Import symkey failed");
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    unsigned char iv[16];
    for (size_t i = 0; i < sizeof(iv); ++i) iv[i] = (unsigned char)(0xA0 + i);
    SECItem param = { siBuffer, iv, sizeof(iv) };

    unsigned char plaintext[32] = {0};
    memcpy(plaintext, "nss aes cbc plaintext", 22);
    unsigned char ciphertext[48] = {0};
    unsigned char recovered[48] = {0};
    unsigned int cipher_len = 0;
    unsigned int recovered_len = 0;

    SECStatus rv = PK11_Encrypt(key, CKM_AES_CBC_PAD, &param,
                                ciphertext, &cipher_len, sizeof(ciphertext),
                                plaintext, sizeof(plaintext));
    if (rv != SECSuccess) {
        bail("PK11_Encrypt failed");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    unsigned char iv_reset[16];
    memcpy(iv_reset, iv, sizeof(iv));
    SECItem dec_param = { siBuffer, iv_reset, sizeof(iv_reset) };
    rv = PK11_Decrypt(key, CKM_AES_CBC_PAD, &dec_param,
                      recovered, &recovered_len, sizeof(recovered),
                      ciphertext, cipher_len);
    if (rv != SECSuccess) {
        bail("PK11_Decrypt failed");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    if (recovered_len != sizeof(plaintext) || memcmp(recovered, plaintext, recovered_len) != 0) {
        fprintf(stderr, "CBC plaintext mismatch\n");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    printf("cbc success len=%u ct_first=0x%02x\n", cipher_len, ciphertext[0]);

    PK11_FreeSymKey(key);
    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
