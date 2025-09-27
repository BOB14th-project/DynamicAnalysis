// old version openssl
// ECDSA sign and verify code
// NID_secp256k1
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h> // SHA256을 위해 추가
#include <string.h>
#include <stdio.h>

int main() {
    // 타원 곡선 키 생성
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (eckey == NULL) {
        printf("Error creating ECC key\n");
        return 1;
    }

    if (!EC_KEY_generate_key(eckey)) {
        printf("Error generating ECC key\n");
        EC_KEY_free(eckey);
        return 1;
    }

    // 공개키 출력
    PEM_write_EC_PUBKEY(stdout, eckey);

    // 서명할 메시지
    const char *message = "Hello, ECC!";
    
    // 1. 메시지를 해싱 (SHA-256 사용)
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)message, strlen(message), digest);

    printf("\nMessage Digest (SHA-256):\n");
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n\n");
    
    // 2. 메시지 '해시'를 서명
    ECDSA_SIG *signature = ECDSA_do_sign(digest, SHA256_DIGEST_LENGTH, eckey);
    if (signature == NULL) {
        printf("Error signing message digest\n");
        EC_KEY_free(eckey);
        return 1;
    }

    // 3. 메시지 '해시'를 검증
    int verify_status = ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, signature, eckey);
    if (verify_status == 1) {
        printf("Signature Verified Successfully\n");
    } else if (verify_status == 0) {
        printf("Signature Verification Failed\n");
    } else { // -1
        printf("Error during verification\n");
    }

    // 메모리 해제
    ECDSA_SIG_free(signature);
    EC_KEY_free(eckey);

    printf("Program finished.\n");
    return 0;
}