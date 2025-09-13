#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <stdexcept>
#include <memory>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

// Custom Deleters for std::unique_ptr to handle OpenSSL objects
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* ptr) const {
        EVP_PKEY_free(ptr);
    }
};

struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* ptr) const {
        EVP_PKEY_CTX_free(ptr);
    }
};

using unique_EVP_PKEY = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using unique_EVP_PKEY_CTX = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;

// Exception-based error handler
void handle_openssl_error() {
    // It's useful to get the error string from OpenSSL's error queue
    char err_buf[256];
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    throw std::runtime_error("OpenSSL Error: " + std::string(err_buf));
}

// 1. EC 키 쌍 생성
unique_EVP_PKEY create_ec_keypair() {
    unique_EVP_PKEY_CTX pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!pctx) handle_openssl_error();

    if (EVP_PKEY_keygen_init(pctx.get()) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) <= 0) handle_openssl_error();

    EVP_PKEY* pkey_ptr = nullptr;
    if (EVP_PKEY_keygen(pctx.get(), &pkey_ptr) <= 0) handle_openssl_error();

    return unique_EVP_PKEY(pkey_ptr);
}

// 2. ECIES 암호화 (수정)
std::vector<unsigned char> ecies_encrypt(EVP_PKEY* public_key, std::string_view plaintext) {
    unique_EVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(public_key, nullptr));
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) handle_openssl_error();

    // ECIES에 사용할 대칭키 암호 알고리즘 설정 (AES-256-GCM)
    // 이 부분이 핵심입니다!
    if (EVP_PKEY_CTX_set_ecies_enc_param(ctx.get(), EVP_aes_256_gcm()) <= 0) {
        handle_openssl_error();
    }

    size_t ciphertext_len = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &ciphertext_len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        handle_openssl_error();
    }

    std::vector<unsigned char> ciphertext(ciphertext_len);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &ciphertext_len,
        reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) <= 0) {
        handle_openssl_error();
    }

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

// 3. ECIES 복호화 (수정)
std::string ecies_decrypt(EVP_PKEY* private_key, const std::vector<unsigned char>& ciphertext) {
    unique_EVP_PKEY_CTX ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) handle_openssl_error();

    // ECIES에 사용할 대칭키 암호 알고리즘 설정 (암호화와 동일해야 함)
    // 이 부분이 핵심입니다!
    if (EVP_PKEY_CTX_set_ecies_enc_param(ctx.get(), EVP_aes_256_gcm()) <= 0) {
        handle_openssl_error();
        // ECIES에 사용할 대칭키 암호 알고리즘 설정 (AES-256-GCM)
        // EVP_PKEY_CTX_set_ecies_enc_param은 OpenSSL 공식 API가 아닙니다.
        // ECIES는 OpenSSL에서 직접 지원하지 않으므로, 아래 줄을 주석 처리하거나 제거해야 합니다.
        // 암호화/복호화는 EVP_PKEY_encrypt/EVP_PKEY_decrypt로만 진행됩니다.

        // if (EVP_PKEY_CTX_set_ecies_enc_param(ctx.get(), EVP_aes_256_gcm()) <= 0) {
        //     handle_openssl_error();
        // }
    }

    size_t decrypted_len = 0;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &decrypted_len, ciphertext.data(), ciphertext.size()) <= 0) {
        handle_openssl_error();
    }

    std::vector<unsigned char> decrypted_buffer(decrypted_len);
    if (EVP_PKEY_decrypt(ctx.get(), decrypted_buffer.data(), &decrypted_len, ciphertext.data(), ciphertext.size()) <= 0) {
        handle_openssl_error();
    }

    return std::string(reinterpret_cast<char*>(decrypted_buffer.data()), decrypted_len);
}

// 헬퍼 함수: 바이트 벡터를 16진수 문자열로 출력
void print_hex(std::string_view title, const std::vector<unsigned char>& data) {
    std::cout << title << " (" << data.size() << " bytes):\n";
    std::cout << std::hex << std::setfill('0');
    for (unsigned char byte : data) {
        std::cout << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::dec << "\n\n";
}

int main() {
    try {
        const std::string message = "This is a secret message for ECIES test in C++.";
        std::cout << "Original Message: \"" << message << "\"\n\n";

        // 1. 키 쌍 생성
        unique_EVP_PKEY receiver_key = create_ec_keypair();
        std::cout << "EC key pair generated successfully.\n\n";

        // 2. 암호화
        std::vector<unsigned char> ciphertext = ecies_encrypt(receiver_key.get(), message);
        print_hex("Ciphertext (Encrypted Data)", ciphertext);

        // 3. 복호화
        std::string decrypted_text = ecies_decrypt(receiver_key.get(), ciphertext);
        std::cout << "Decryption successful.\n\n";
        std::cout << "Decrypted Message: \"" << decrypted_text << "\"\n\n";

        // 4. 결과 검증
        if (message == decrypted_text) {
            std::cout << "Success: Original and decrypted messages are identical.\n";
        }
        else {
            std::cout << "Failure: Messages do not match.\n";
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Caught exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}