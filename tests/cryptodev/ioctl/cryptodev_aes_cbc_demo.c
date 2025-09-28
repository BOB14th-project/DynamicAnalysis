// cryptodev_aes_cbc_demo.c
// Opens /dev/crypto, establishes an AES-CBC session, then closes it so the
// cryptodev hook can record the key material supplied via CIOCGSESSION.

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
        return 0; // treat as no-op when device is absent
    }

    unsigned char key[32];
    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (unsigned char)(i * 3);
    }

    struct session_op sess;
    memset(&sess, 0, sizeof(sess));
    sess.cipher = CRYPTO_AES_CBC;
    sess.keylen = sizeof(key);
    sess.key = key;

    if (ioctl(fd, CIOCGSESSION, &sess) == -1) {
        perror("CIOCGSESSION");
        close(fd);
        return 1;
    }

    printf("cryptodev AES-CBC session established (ses=%u)\n", sess.ses);

    if (ioctl(fd, CIOCFSESSION, &sess.ses) == -1) {
        perror("CIOCFSESSION");
    }

    close(fd);
    return 0;
}
