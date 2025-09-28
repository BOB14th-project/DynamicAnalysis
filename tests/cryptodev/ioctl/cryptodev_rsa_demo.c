// cryptodev_rsa_demo.c
// Attempts to perform a basic RSA modular exponentiation via cryptodev's
// CIOCKEY interface so the hook can observe crypt_kop parameters.

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

    // Extremely small toy RSA numbers (not secure!)
    unsigned char modulus[] = { 0xC7, 0x53, 0x6B, 0x89, 0x51 }; // arbitrary bytes
    unsigned char exponent[] = { 0x01, 0x00, 0x01 }; // 65537
    unsigned char base[]     = { 0x12, 0x34, 0x56, 0x78, 0x9A };

    struct crypt_kop kop;
    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_MOD_EXP;
    kop.crk_iparams = 3;
    kop.crk_param[0].crp_p = reinterpret_cast<caddr_t>(base);
    kop.crk_param[0].crp_n = sizeof(base);
    kop.crk_param[1].crp_p = reinterpret_cast<caddr_t>(exponent);
    kop.crk_param[1].crp_n = sizeof(exponent);
    kop.crk_param[2].crp_p = reinterpret_cast<caddr_t>(modulus);
    kop.crk_param[2].crp_n = sizeof(modulus);

    if (ioctl(fd, CIOCKEY, &kop) == -1) {
        perror("CIOCKEY");
        close(fd);
        return 0;
    }

    printf("cryptodev RSA demo invoked CIOCKEY (status=%d)\n", kop.crk_status);

    close(fd);
    return 0;
}
