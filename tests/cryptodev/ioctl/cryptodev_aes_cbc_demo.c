// cryptodev_aes_cbc_demo.c
// Demonstrates AES-256-CBC via /dev/crypto (cryptodev).
// Requires cryptodev kernel module and libcrypto.
// Build: gcc cryptodev_aes_cbc_demo.c -lcrypto -o cryptodev_aes_cbc_demo

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
        return 1;
    }

    struct session_op sess = {0};
    unsigned char key[32] = {0};
    sess.cipher = CRYPTO_AES_CBC;
    sess.keylen = sizeof(key);
    sess.key = key;

    if (ioctl(fd, CIOCGSESSION, &sess) < 0) {
        perror("CIOCGSESSION");
        close(fd);
        return 1;
    }

    unsigned char iv[16] = {0};
    unsigned char src[] = "hello from cryptodev";
    unsigned char dst[64] = {0};

    struct crypt_op cop = {0};
    cop.ses = sess.ses;
    cop.len = sizeof(src) - 1;
    cop.src = src;
    cop.dst = dst;
    cop.iv = iv;
    cop.op = COP_ENCRYPT;

    if (ioctl(fd, CIOCCRYPT, &cop) < 0) {
        perror("CIOCCRYPT");
    } else {
        printf("ciphertext first byte=0x%02x\n", dst[0]);
    }

    ioctl(fd, CIOCFSESSION, &sess.ses); // ignore errors
    close(fd);
    return 0;
}
