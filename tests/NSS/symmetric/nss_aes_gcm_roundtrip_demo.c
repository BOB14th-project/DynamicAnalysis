// nss_aes_gcm_roundtrip_demo.c
// AES-256-GCM encryption and decryption using Mozilla NSS PK11_Encrypt/PK11_Decrypt APIs.

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

    unsigned char key_bytes[32] = {0};
    SECItem keyItem = { siBuffer, key_bytes, sizeof(key_bytes) };
    PK11SymKey* key = PK11_ImportSymKey(slot, CKM_AES_GCM, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);
    if (!key) {
        bail("Import symkey failed");
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    unsigned char iv[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    CK_GCM_PARAMS params = {
        .pIv = iv,
        .ulIvLen = sizeof(iv),
        .ulIvBits = sizeof(iv) * 8,
        .pAAD = (unsigned char*)"nss-aad",
        .ulAADLen = 7,
        .ulTagBits = 16 * 8,
    };
    SECItem param = { siBuffer, (unsigned char*)&params, sizeof(params) };

    const unsigned char plaintext[] = "nss aes gcm roundtrip";
    unsigned char ciphertext[128] = {0};
    unsigned char recovered[128] = {0};
    unsigned int cipher_len = 0;
    unsigned int plain_len = 0;

    SECStatus rv = PK11_Encrypt(key, CKM_AES_GCM, &param,
                                ciphertext, &cipher_len, sizeof(ciphertext),
                                plaintext, sizeof(plaintext) - 1);
    if (rv != SECSuccess) {
        bail("PK11_Encrypt failed");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    CK_GCM_PARAMS dec_params = params;
    SECItem dec_item = { siBuffer, (unsigned char*)&dec_params, sizeof(dec_params) };
    rv = PK11_Decrypt(key, CKM_AES_GCM, &dec_item,
                      recovered, &plain_len, sizeof(recovered),
                      ciphertext, cipher_len);
    if (rv != SECSuccess) {
        bail("PK11_Decrypt failed");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    if (plain_len != sizeof(plaintext) - 1 || memcmp(recovered, plaintext, plain_len) != 0) {
        fprintf(stderr, "plaintext mismatch\n");
        PK11_FreeSymKey(key);
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    printf("roundtrip success len=%u ct_first=0x%02x tag_first=0x%02x\n",
           cipher_len, ciphertext[0], ciphertext[cipher_len - 16]);

    PK11_FreeSymKey(key);
    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
