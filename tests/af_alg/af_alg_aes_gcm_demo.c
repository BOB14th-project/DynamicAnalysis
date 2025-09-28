// af_alg_aes_gcm_demo.c
// Minimal AF_ALG sample that binds to the kernel AES skcipher interface and
// sets a key so the AF_ALG hook can observe ALG_SET_KEY usage.

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
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, "cbc(aes)");

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("bind");
        close(sock);
        return 1;
    }

    unsigned char key[16];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)i;
    }

    if (setsockopt(sock, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) == -1) {
        perror("setsockopt(ALG_SET_KEY)");
        close(sock);
        return 1;
    }

    printf("AF_ALG demo set a %zu-byte AES key\n", sizeof(key));

    close(sock);
    return 0;
}
