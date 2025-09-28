// af_alg_hmac_sha256_demo.c
// Binds to the AF_ALG hash interface using hmac(sha256) and sets a MAC key
// to ensure the hook records ALG_SET_KEY for hash algorithms.

#include <linux/if_alg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    int sock = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_alg sa;
    memset(&sa, 0, sizeof(sa));
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, "hmac(sha256)");

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)(i + 1);
    }

    if (setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) {
        perror("setsockopt(ALG_SET_KEY)");
        close(sock);
        return 1;
    }

    printf("AF_ALG HMAC demo set a %zu-byte key\n", sizeof(key));

    close(sock);
    return 0;
}
