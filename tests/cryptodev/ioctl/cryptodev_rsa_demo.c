// cryptodev_rsa_demo.c
// Attempts to perform a basic RSA modular exponentiation via cryptodev's
// CIOCKEY interface so the hook can observe crypt_kop parameters.

#include <crypto/cryptodev.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// Define caddr_t if not available
#ifndef caddr_t
typedef char * caddr_t;
#endif

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
    kop.crk_param[0].crp_p = (caddr_t)base;
    kop.crk_param[0].crp_nbits = sizeof(base) * 8;
    kop.crk_param[1].crp_p = (caddr_t)exponent;
    kop.crk_param[1].crp_nbits = sizeof(exponent) * 8;
    kop.crk_param[2].crp_p = (caddr_t)modulus;
    kop.crk_param[2].crp_nbits = sizeof(modulus) * 8;

    if (ioctl(fd, CIOCKEY, &kop) == -1) {
        perror("CIOCKEY");
        close(fd);
        return 0;
    }

    printf("cryptodev RSA modular exponentiation invoked CIOCKEY (status=%d)\n", kop.crk_status);

    // Extended test: attempt RSA signing operation (may fail if not supported)
    // This tests the enhanced parameter parsing for asymmetric operations
    unsigned char message_digest[] = {
        0x2c, 0xf2, 0x4d, 0xba, 0x4f, 0x21, 0xd4, 0x28, 0x8e, 0xb8, 0xc2, 0x4a, 0x29, 0xa3, 0x4e, 0x8b,
        0x65, 0x3a, 0x7d, 0xbf, 0x2c, 0xf2, 0x4d, 0xba, 0x4f, 0x21, 0xd4, 0x28, 0x8e, 0xb8, 0xc2, 0x4a
    }; // Mock SHA-256 digest

    unsigned char rsa_n[] = {
        0xc7, 0x53, 0x6b, 0x89, 0x51, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b,
        0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b
    }; // Mock 256-bit RSA modulus

    unsigned char rsa_d[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    }; // Mock RSA private exponent

    printf("Testing extended RSA signing operation...\n");

    struct crypt_kop kop_sign;
    memset(&kop_sign, 0, sizeof(kop_sign));
    kop_sign.crk_op = 5; // CRK_RSA_SIGN (extended operation)
    kop_sign.crk_iparams = 3;
    kop_sign.crk_oparams = 1;

    // Set up parameters: digest, modulus, private exponent
    kop_sign.crk_param[0].crp_p = (caddr_t)message_digest;
    kop_sign.crk_param[0].crp_nbits = sizeof(message_digest) * 8;
    kop_sign.crk_param[1].crp_p = (caddr_t)rsa_n;
    kop_sign.crk_param[1].crp_nbits = sizeof(rsa_n) * 8;
    kop_sign.crk_param[2].crp_p = (caddr_t)rsa_d;
    kop_sign.crk_param[2].crp_nbits = sizeof(rsa_d) * 8;

    if (ioctl(fd, CIOCKEY, &kop_sign) == -1) {
        printf("RSA signing operation not supported (expected): %m\n");
    } else {
        printf("RSA signing operation completed (status=%d)\n", kop_sign.crk_status);
    }

    close(fd);
    return 0;
}
