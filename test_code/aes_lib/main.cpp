#include <iostream>
#include <iomanip>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>

// AES-256-CBC 암호화 함수
std::vector<unsigned char> aes_encrypt(const std::vector<unsigned char>& plaintext,
                                       const std::vector<unsigned char>& key,
                                       const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

int main() {
    // 32바이트 키와 16바이트 IV 생성
    std::vector<unsigned char> key(32), iv(16);
    RAND_bytes(key.data(), key.size());
    RAND_bytes(iv.data(), iv.size());

    // 암호화할 평문
    std::string plain = "Hello, AES encryption with OpenSSL!";
    std::vector<unsigned char> plaintext(plain.begin(), plain.end());

    // 암호화
    std::vector<unsigned char> ciphertext = aes_encrypt(plaintext, key, iv);

    // 결과 출력
    std::cout << "Ciphertext (hex): ";
    for (unsigned char c : ciphertext)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    std::cout << std::endl;

    return 0;
}