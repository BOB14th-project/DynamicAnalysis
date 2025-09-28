// nss_aes_gcm_demo.c
// Minimal AES-256-GCM example using Mozilla NSS crypto APIs.
// Build (requires NSS development headers/libraries):
//   gcc nss_aes_gcm_demo.c -lnss3 -lnspr4 -lplds4 -lplc4 -o nss_aes_gcm_demo

#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/secerr.h>
#include <nspr/prinit.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS init failed\n");
        return 1;
    }

    PK11SlotInfo* slot = PK11_GetInternalSlot();
    if (!slot) {
        fprintf(stderr, "No internal slot\n");
        return 1;
    }

    unsigned char key_bytes[32] = {0};
    SECItem keyItem = { siBuffer, key_bytes, sizeof(key_bytes) };
    PK11SymKey* symKey = PK11_ImportSymKey(slot, CKM_AES_GCM, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);
    if (!symKey) {
        fprintf(stderr, "Import sym key failed: %d\n", PORT_GetError());
        PK11_FreeSlot(slot);
        NSS_Shutdown();
        return 1;
    }

    unsigned char iv[12] = {0};
    CK_GCM_PARAMS params = { .pIv = iv, .ulIvLen = sizeof(iv), .ulIvBits = sizeof(iv) * 8,
                             .pAAD = NULL, .ulAADLen = 0, .ulTagBits = 16 * 8 };
    SECItem param = { siBuffer, (unsigned char*)&params, sizeof(params) };

    unsigned char plaintext[] = "hello from nss";
    unsigned char ciphertext[64] = {0};
    unsigned int outLen = 0;

    SECStatus rv = PK11_Encrypt(symKey, CKM_AES_GCM, &param,
                                ciphertext, &outLen, sizeof(ciphertext),
                                plaintext, sizeof(plaintext)-1);
    printf("encrypt status=%d len=%u first=0x%02x\n", rv, outLen, ciphertext[0]);

    PK11_FreeSymKey(symKey);
    PK11_FreeSlot(slot);
    NSS_Shutdown();
    return 0;
}
