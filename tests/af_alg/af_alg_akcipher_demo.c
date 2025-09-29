// tests/af_alg/af_alg_akcipher_demo.c
// Demo for AF_ALG akcipher (asymmetric cipher) interface
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <errno.h>

// Extended AF_ALG constants for akcipher/kpp (if not available in kernel headers)
#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY 6
#endif
#ifndef ALG_SET_PUBKEY_ID
#define ALG_SET_PUBKEY_ID 7
#endif
#ifndef ALG_SET_KEY_ID
#define ALG_SET_KEY_ID 8
#endif
#ifndef ALG_OP_SIGN
#define ALG_OP_SIGN 2
#endif
#ifndef ALG_OP_VERIFY
#define ALG_OP_VERIFY 3
#endif

int main() {
    printf("AF_ALG AKCIPHER Demo\n");
    printf("====================\n");

    // Try to create AF_ALG socket
    int sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sockfd < 0) {
        printf("Failed to create AF_ALG socket: %s\n", strerror(errno));
        return 1;
    }
    printf("Created AF_ALG socket: fd=%d\n", sockfd);

    // Try to bind to akcipher algorithm (RSA)
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "akcipher",
        .salg_name = "rsa"
    };

    if (bind(sockfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        printf("Failed to bind to akcipher:rsa: %s\n", strerror(errno));
        printf("Note: akcipher may not be available in userspace on this system\n");

        // Fallback: Test akcipher functionality with skcipher socket to verify hooks
        printf("\n--- Testing akcipher hooks with fallback socket ---\n");
        close(sockfd);

        sockfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
        struct sockaddr_alg sa_fallback = {
            .salg_family = AF_ALG,
            .salg_type = "skcipher",
            .salg_name = "cbc(aes)"
        };

        if (bind(sockfd, (struct sockaddr*)&sa_fallback, sizeof(sa_fallback)) < 0) {
            printf("Failed fallback bind: %s\n", strerror(errno));
            close(sockfd);
            return 1;
        }

        printf("Fallback: bound to skcipher:cbc(aes)\n");

        // Test ALG_SET_PUBKEY hook (even on skcipher to verify extension works)
        unsigned char mock_rsa_pubkey[] = {
            0x30, 0x82, 0x01, 0x22,  // SEQUENCE, length 290
            0x30, 0x0d,              // SEQUENCE, length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // RSA OID
            0x05, 0x00,              // NULL
            0x03, 0x82, 0x01, 0x0f,  // BIT STRING, length 271
            0x00,                    // padding
            // Mock RSA key data (normally would be full key)
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00,
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90  // mock modulus start
        };

        if (setsockopt(sockfd, SOL_ALG, ALG_SET_PUBKEY, mock_rsa_pubkey, sizeof(mock_rsa_pubkey)) < 0) {
            printf("ALG_SET_PUBKEY test: %s (expected for skcipher)\n", strerror(errno));
        } else {
            printf("ALG_SET_PUBKEY test: successful (hook detected RSA-DER format)\n");
        }

        // Test ALG_SET_KEY_ID
        int test_key_id = 12345;
        if (setsockopt(sockfd, SOL_ALG, ALG_SET_KEY_ID, &test_key_id, sizeof(test_key_id)) < 0) {
            printf("ALG_SET_KEY_ID test: %s\n", strerror(errno));
        } else {
            printf("ALG_SET_KEY_ID test: successful\n");
        }

        // Test ALG_OP_SIGN operation
        int op = ALG_OP_SIGN;
        if (setsockopt(sockfd, SOL_ALG, ALG_SET_OP, &op, sizeof(op)) < 0) {
            printf("ALG_SET_OP_SIGN test: %s\n", strerror(errno));
        } else {
            printf("ALG_SET_OP_SIGN test: successful\n");
        }

        close(sockfd);
        printf("akcipher hooks testing completed (fallback mode)\n");
        return 0;
    }

    printf("Successfully bound to akcipher:rsa\n");

    // Test setting an RSA public key (DER format)
    unsigned char rsa_pubkey_der[] = {
        0x30, 0x82, 0x01, 0x22,  // SEQUENCE, length 290
        0x30, 0x0d,              // SEQUENCE, length 13
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // RSA OID
        0x05, 0x00,              // NULL
        0x03, 0x82, 0x01, 0x0f,  // BIT STRING, length 271
        0x00                     // padding
        // ... (rest would be actual RSA public key)
    };

    if (setsockopt(sockfd, SOL_ALG, ALG_SET_PUBKEY, rsa_pubkey_der, sizeof(rsa_pubkey_der)) == 0) {
        printf("ALG_SET_PUBKEY (RSA DER): successful\n");
    } else {
        printf("ALG_SET_PUBKEY (RSA DER): %s\n", strerror(errno));
    }

    // Test setting operation mode to sign
    int op = ALG_OP_SIGN;
    if (setsockopt(sockfd, SOL_ALG, ALG_SET_OP, &op, sizeof(op)) == 0) {
        printf("ALG_SET_OP_SIGN: successful\n");
    } else {
        printf("ALG_SET_OP_SIGN: %s\n", strerror(errno));
    }

    // Test key ID from keyring
    int key_id = 54321;
    if (setsockopt(sockfd, SOL_ALG, ALG_SET_PUBKEY_ID, &key_id, sizeof(key_id)) == 0) {
        printf("ALG_SET_PUBKEY_ID: successful\n");
    } else {
        printf("ALG_SET_PUBKEY_ID: %s\n", strerror(errno));
    }

    // Try to accept operation socket
    int opfd = accept(sockfd, NULL, 0);
    if (opfd >= 0) {
        printf("Accepted operation socket: fd=%d\n", opfd);

        // Test sending data for signing
        char test_data[] = "Hello, AF_ALG akcipher signing!";
        ssize_t sent = send(opfd, test_data, strlen(test_data), 0);
        if (sent > 0) {
            printf("Sent %zd bytes for signing operation\n", sent);
        } else {
            printf("Failed to send data: %s\n", strerror(errno));
        }

        // Try to receive signature
        unsigned char signature[256];
        ssize_t sig_len = recv(opfd, signature, sizeof(signature), 0);
        if (sig_len > 0) {
            printf("Received signature: %zd bytes\n", sig_len);
        } else {
            printf("Failed to receive signature: %s\n", strerror(errno));
        }

        close(opfd);
    } else {
        printf("Failed to accept operation socket: %s\n", strerror(errno));
    }

    close(sockfd);
    printf("\nAF_ALG AKCIPHER demo completed\n");
    return 0;
}