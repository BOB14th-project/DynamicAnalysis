// af_alg_skcipher_aes_cbc_demo.c
// Demonstrates AF_ALG skcipher interface with AES-CBC to provide coverage for
// symmetric encryption key/IV handling.

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, "cbc(aes)");

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)(i + 0x10);
    if (setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) {
        perror("ALG_SET_KEY");
        close(sock);
        return 1;
    }

    int op = ALG_OP_ENCRYPT;
    (void)setsockopt(sock, SOL_ALG, ALG_SET_OP, &op, sizeof(op));

    printf("AF_ALG skcipher demo set a %zu-byte AES key\n", sizeof(key));
    close(sock);
    return 0;
}
