// cryptodev_hmac_sha256_demo.c
// Establishes an HMAC-SHA256 session so the cryptodev hook can observe
// CIOCGSESSION for MAC algorithms.

#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) {
        perror("open /dev/crypto");
        return 0;
    }

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = (unsigned char)(0xAA + i);

    struct session_op sess;
    memset(&sess, 0, sizeof(sess));
    sess.cipher = CRYPTO_SHA2_256_HMAC;
    sess.keylen = sizeof(key);
    sess.key = key;

    if (ioctl(fd, CIOCGSESSION, &sess) == -1) {
        perror("CIOCGSESSION");
        close(fd);
        return 1;
    }

    printf("cryptodev HMAC session established (ses=%u)\n", sess.ses);

    if (ioctl(fd, CIOCFSESSION, &sess.ses) == -1) {
        perror("CIOCFSESSION");
    }

    close(fd);
    return 0;
}
